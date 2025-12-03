import logging
import requests
from cryptography import x509, exceptions
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
from cryptography.x509 import ocsp, ExtendedKeyUsageOID, UnrecognizedExtension
from cryptography.x509.oid import ExtensionOID, NameOID
from datetime import datetime, timezone
from requests.exceptions import RequestException
from typing import Tuple, Optional
from urllib3.exceptions import NameResolutionError
from utils.x509 import fetch_issuer_certificate
from utils.misc import get_hash_algorithm_from_oid, get_ocsp_oid_name

def check_cert_chain_revocation(cert_chain: list[x509.Certificate], stapled_response: bytes, timeout: int = 10) -> Tuple[bool, str, Optional[int], Optional[str], Optional[str]]:
    """
    Check if any certificate in a chain has been revoked using CRL and/or OCSP.
    
    Args:
        cert_chain:         List of x509.Certificate objects, ordered from leaf to root [leaf_cert, intermediate_cert(s), root_cert]
        stapled_response:   OCSP bytes retrieved from stapled response during TLS session negotiation.
        timeout:            Request timeout in seconds (default: 10)
    
    Returns:
        Tuple of (is_revoked: bool, revocation_reasons: Optional[str], error_messages: str)
        - (True, revocation_reasons, error_messages) if any cert is revoked
        - (False, None, None) if all certificates are confirmed valid
        - (False, None, error_messages) if checks failed
    """
    logging.warning(f"-----------------------------------Entering check_cert_chain_revocation()-------------------------")
    
    skip = 1  # Skip root for revocation checking.

    if len(cert_chain) == 1:
        if cert_chain[0].subject == cert_chain[0].issuer:
            logging.warning('return (Skipping revocation check for self-signed cert.')
            return (False, "⚠️ Revocation checks skipped for self-signed cert.")
        else:
            # If not self-signed / root, implies incomplete certificate chain. Proceed with revocation checking in this case.
            skip = 0 
    elif cert_chain[-1].subject != cert_chain[-1].issuer:
            # Implies incomplete chain, where chain_builder() was unable to identify a trusted root certificate.  
            # In this case, check revocation for all certs in chain.
            skip = 0
    
    # Check each certificate in the chain (except true root CA certs)
    all_errors = []
    revoked = False

    for i in range(len(cert_chain) - skip):
        cert = cert_chain[i]
        issuer = cert_chain[i + 1] if i + 1 < len(cert_chain) else None

        # Get certificate common name for logging messages
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = ""
        
        if i == 0 and stapled_response:
            is_revoked, error, reason, method = check_cert_revocation(cert, issuer, cert_chain, timeout, stapled_response)
        else:
            is_revoked, error, reason, method = check_cert_revocation(cert, issuer, cert_chain, timeout)
        
        if is_revoked:
            revoked = True
            logging.error(f'Cert #{i} ({cn}) is revoked per {method}. \nReason: {reason}')
            all_errors.append(f"<br>&emsp;&emsp;▶ Cert #{i} (<code>{cn}</code>) is revoked per {method}<br>&emsp;&emsp;<b>Reason:</b> {reason}") #########
        
        if error:
            all_errors.append(f"⚠️ Error while checking revocation for cert #{i} (<code>{cn}</code>):<br>&emsp;&emsp;▶ {error}")
    
    # If we checked all certs and none were revoked
    if not all_errors and not revoked:
        return (False, None)

    error_msg = "<br>".join(all_errors)
    if revoked:
        return (True, error_msg)
    else:
        # If we had errors but no confirmed revocations
        return (False, error_msg)

def check_cert_revocation(cert: x509.Certificate, issuer_cert: x509.Certificate | None, cert_chain: list[x509.Certificate], timeout: int = 10, stapled_response = None) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """
    Check if a certificate has been revoked using CRL and/or OCSP.
    
    Args:
        cert:        The x509.Certificate object to check
        issuer_cert: The issuing CA that signed the cert whose revocation status is being checked
        cert_chain:  The certificate chain for the TLS connection (required for OCSP checks)
        timeout:     Request timeout in seconds (default: 10)
    
    Returns:
        Tuple of (is_revoked: bool, error_message: str, revocation_reason: Optional[str], method: Optional[str])
        - (True, "", "reason_code", "CRL/OCSP") if certificate is confirmed revoked
        - (False, "", None, None) if certificate is confirmed valid
        - (False, "error message", None, None) if check failed
    """
    logging.warning(f"-----------------------------------Entering check_cert_revocation()-------------------------------")
    logging.info(f"Checking revocation for {cert.subject.rfc4514_string()}")

    crl_result = None
    ocsp_result = None
    errors = []
    return_msg: str = None

    # If working with unchained cert (or incomplete chain), attempt to fetch Issuer cert
    if issuer_cert == None:
        logging.warning('Incomplete certificate chain; attempting to fetch issuer CA cert.')
        issuer_cert = fetch_issuer_certificate(cert)
    if not issuer_cert:
        error_msg = (f'Unable to fetch Issuer cert to perform revocation checks.')
        logging.error(error_msg)
        return (False, error_msg, None, None)

    # Try OCSP first
    if stapled_response:   # Check for stapled OCSP response bytes before attempting to perform online status query
        logging.debug('Verifying against TLS-stapled OCSP response.')
        try:
            ocsp_result, return_msg = _check_ocsp(cert, issuer_cert, cert_chain, stapled_response)
        except Exception as e:
            errors.append(f"OCSP check for stapled response failed: {str(e)}")
    else:
        try:
            ocsp_urls = _get_ocsp_urls(cert)
            logging.debug(f'OCSP URLs extracted: {ocsp_urls}')
            if ocsp_urls:
                ocsp_result, return_msg = _get_ocsp(cert, issuer_cert, cert_chain, ocsp_urls, timeout)
        except Exception as e:
            errors.append(f"OCSP check failed against fetched OCSP status: {str(e)}")   

    if ocsp_result is True:  # Explicitly revoked
        return (True, "", return_msg, "OCSP")
    elif ocsp_result is False:  # Explicitly not revoked
        return (False, "", None, None)
    else:
        logging.info('Unable to check revocation via OCSP; falling back to CRL (if CDP present).')
        if return_msg: errors.append(return_msg)
    
    # Try CRL as fallback
    try:
        crl_urls = _get_crl_urls(cert)
        crl_errors = []
        if crl_urls:
            crl_result, crl_reason, crl_errors = _check_crl(cert, crl_urls, issuer_cert, timeout)
            if crl_result is True:  # Explicitly revoked
                return (True, "", crl_reason, "CRL")
            elif crl_result is False: 
                return (False, "", None, None)
            else:
                if crl_errors: errors.extend(crl_errors)
    except Exception as e:
        errors.append(f"CRL check failed: {str(e)}")

    # If we got here, we couldn't definitively check revocation
    if not ocsp_urls and not crl_urls:
        return (False, "No revocation information (CRL/OCSP) in certificate", None, None)
    
    error_msg = "<br>".join(errors) if errors else "Unable to verify revocation status"
    return (False, error_msg, None, None)

def _get_crl_revocation_reason(revoked_cert) -> Optional[str]:
    """Extract revocation reason from a RevokedCertificate object."""

    try:
        # Check if revoked_cert has extensions
        if not hasattr(revoked_cert, 'extensions'):
            return "UNSPECIFIED"
        
        try:
            extensions = revoked_cert.extensions
            
            # OID 2.5.29.21 = CRL extension field for revocation reason code
            crl_reason_oid = x509.oid.ObjectIdentifier("2.5.29.21")
            reason_ext = extensions.get_extension_for_oid(crl_reason_oid)
            
            # Extract the reason value & revocation timestamp
            reason_value = reason_ext.value
            revocation_time = revoked_cert.revocation_date_utc

            # Access the reason attribute which is a ReasonFlags enum
            if hasattr(reason_value, 'reason'):
                # Return the enum name (e.g., "key_compromise")
                reason = reason_value.reason.name.upper()
            else:
                reason = "UNSPECIFIED"
            
            logging.error(f'Cert revoked at {revocation_time.strftime("%Y-%m-%dZ%H:%M:%S")} due to: {reason}')
            return f'{reason} on {revocation_time.strftime("%B %d, %Y")}'
            
        except x509.ExtensionNotFound:
            # No reason extension means unspecified per RFC 5280
            return "UNSPECIFIED"
        except AttributeError as e:
            logging.error(
                f"AttributeError accessing reason: {e}, reason_ext type: {type(reason_ext) if 'reason_ext' in locals() else 'N/A'}, value type: {type(reason_value) if 'reason_value' in locals() else 'N/A'}")
            return "UNSPECIFIED"
        
    except Exception as e:
        # Unexpected error, but return unspecified rather than failing
        logging.error(f"Unexpected error in _get_crl_revocation_reason: {e}")
        return "UNSPECIFIED"

def _get_ocsp_urls(cert: x509.Certificate) -> list:
    """Extract OCSP URLs from certificate's Authority Information Access extension."""
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        urls = []
        for desc in aia:
            if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                urls.append(desc.access_location.value)
        logging.debug(f'Extracted OCSP server(s) from cert: {urls}')
        return urls
    except x509.ExtensionNotFound:
        return []

def _get_crl_urls(cert: x509.Certificate) -> list:
    """Extract CRL URLs from certificate's CRL Distribution Points (CDP) extension."""
    logging.warning(f"-----------------------------------Entering _get_crl_urls()---------------------------------------")
    try:
        crl_dp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        
        urls = []
        for dp in crl_dp:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
        logging.debug(f'Extracted CRL Distribution Point (CDP) server(s) from cert: {urls}')
        return urls
    except x509.ExtensionNotFound:
        logging.warning('No CRL Distribution Point URLs identified.')
        return []

def _get_ocsp(cert: x509.Certificate, issuer_cert: x509.Certificate, cert_chain: list[x509.Certificate], ocsp_urls: list, timeout: int ) -> Tuple[Optional[bool], Optional[str]]:
    """
    Check certificate status via OCSP.
    Returns (True, reason) if revoked, (False, None) if good, (None, None) if unknown/error.
    """
    logging.warning(f"-----------------------------------Entering _get_ocsp()-------------------------------------------")
    # Build OCSP request
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1()) 
    req = builder.build()
    req_data = req.public_bytes(serialization.Encoding.DER)

    # Try each OCSP URL
    exception_messages = []
    for url in ocsp_urls:
        headers = {
            'Content-Type': 'application/ocsp-request',
            'Accept': 'application/ocsp-response'
        }
        
        logging.debug(f'Querying OCSP server {url} for cert serial number {cert.serial_number}')
        try:
            response = requests.post(url, data=req_data, headers=headers, timeout=timeout)
        
        except NameResolutionError as e:
            exception_msg = f'DNS resolution failed for OCSP responder {url}'
            logging.error(exception_msg + f':\n --> {e}')
            exception_messages.append(exception_msg)
            continue 

        except RequestException as e:
            exception_msg = f"Error querying <code>{url}</code>."
            logging.error(f'Exception encountered: {e}')
            exception_messages.append(exception_msg)
            continue

        except Exception as e:
            exception_msg = f'Encountered other exception trying to query OCSP server:\n{e}'
            logging.error(exception_msg)
            exception_messages.append(exception_msg)
            continue
        
        if response.status_code != 200:
            error_msg = f'Received HTTP response code {response.status_code} querying OCSP server; skipping server.'
            logging.error(error_msg)
            exception_messages.append(error_msg)
            continue
        
        else: # response.status_code == 200:
            revoked, return_msg = _check_ocsp(cert, issuer_cert, cert_chain, response.content)
            #exception_messages.append(return_msg)
            return revoked, return_msg
    
    # Fall through
    return None, exception_messages
        
def _check_ocsp(cert: x509.Certificate, issuer_cert: x509.Certificate, cert_chain: list[x509.Certificate], ocsp_response_bytes ) -> Tuple[Optional[bool], Optional[str]]:
    """
    Check OCSP response data
    Returns (True, reason) if revoked, (False, None) if good, (None, None) if unknown/error.
    """
    logging.warning(f"-----------------------------------Entering _check_ocsp()-----------------------------------------")
    
    try:
        ocsp_resp = ocsp.load_der_ocsp_response(ocsp_response_bytes)
    except ValueError as e:
        exception_msg = f"Error parsing OCSP response: {e}"
        logging.error(exception_msg)
        return None, exception_msg
    except Exception as e:
        exception_msg = f"Error parsing OCSP response: {e}"
        logging.error(exception_msg)
        return None, exception_msg

    if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
        logging.debug("Received successful OCSP response data.")
    elif ocsp_resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
        error_msg = f"The OCSP responder is unauthorized to respond."
        logging.error(error_msg)
        return None, error_msg
    elif ocsp_resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST:
        error_msg = "The OCSP request was malformed; skipping server."
        logging.error(error_msg)
        return None, error_msg
    else:
        error_msg = f"A non-successful OCSP status response was received: {ocsp_resp.response_status.name}; skipping server."
        logging.error(error_msg)
        return None, error_msg
    
    # Log info about cert being checked & OCSP response data for debugging purposes
    logging.debug("OCSP Response Details:")
    
    # Must convert iterator to list, otherwise length check consumes the iterator.
    single_responses = list(ocsp_resp.responses)
    response_count = len(single_responses)
    logging.debug(f'Number of cert status entries inside OCSP response: {response_count}')
    matched_single_resp = None

    for idx, single_resp in enumerate(single_responses):
        if single_resp.serial_number == cert.serial_number:
            logging.debug(f"Matched Single Response at index {idx}")
            logging.debug(f" - Cert Serial Number:  {single_resp.serial_number}")
            logging.debug(f" - Serial Number (Hex): {hex(single_resp.serial_number)}")
            logging.debug(f" - Certificate Status:  {single_resp.certificate_status.name}")
            logging.debug(f" - This Update:         {single_resp.this_update_utc}")
            logging.debug(f" - Next Update:         {single_resp.next_update_utc}")
            matched_single_resp = single_resp
            matched_index = idx

        if single_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            logging.debug(f" - Revocation Time:     {single_resp.revocation_time_utc}")
            if single_resp.revocation_reason:
                logging.debug(f" - Revocation Reason:   {single_resp.revocation_reason.name}")
            else:
                logging.debug(" - Revocation Reason:   UNSPECIFIED")

    if matched_single_resp is None:
        error_msg = "OCSP response did not contain a SingleResponse for this certificate."
        logging.error(error_msg)
        return None, error_msg

    # Log response metadata
    if ocsp_resp.responder_key_hash:
        logging.debug(f" - Responder Key Hash:  {ocsp_resp.responder_key_hash.hex()}")
    if ocsp_resp.responder_name:
        logging.debug(f" - Responder Name:      {ocsp_resp.responder_name}")
    logging.debug(f" - Produced At:         {ocsp_resp.produced_at_utc}")
    logging.debug(f" - Signature Hash Algo: {ocsp_resp.signature_hash_algorithm.name}")
    
    # Log any extensions present in OCSP response
    if response_count == 1:  # Use the Cryptography library only if handling one SINGLERESP object
        try:
            extensions = ocsp_resp.single_extensions
            if extensions:
                logging.debug(f"Found {len(extensions)} extension(s) in OCSP response.")
                for ext in extensions:   
                    oid_name = get_ocsp_oid_name(ext.oid.dotted_string) 
                    if oid_name == 'unknown':
                        oid_name = ext.oid._name if hasattr(ext.oid, '_name') else 'Unknown'
                    logging.debug(f" - Extension OID:       {ext.oid.dotted_string} ({oid_name})")
                    logging.debug(f" - Extension Critical:  {ext.critical}")
                    # Try to display the extension value
                    if isinstance(ext.value, UnrecognizedExtension):
                        value_bytes = ext.value.value
                    else:
                        value_bytes = ext.value
                    logging.debug(f" - Extension Value:     {repr(value_bytes)}")
        except AttributeError:
            logging.debug("No extensions present in OCSP response")
        except Exception as e:
            logging.warning(f"Error parsing OCSP extensions: {e}")

    else:  # Cryptography library doesn't expose extensions for multiple SINGLERESP objects, so parse the ASN.1 bytes directly
        try:
            extensions = extract_single_response_extensions(ocsp_response_bytes, matched_index)
        except Exception as e:
            logging.warning(f"Error parsing OCSP extensions with asn1crypto: {e}")
    
    signature_verified = validate_ocsp_signature(ocsp_resp, cert_chain, issuer_cert)
    if not signature_verified:
        error_msg = f'Digitial signature verification on OCSP response failed.'
        logging.error(error_msg)
        return None, error_msg
    cert_status = matched_single_resp.certificate_status
    if cert_status == ocsp.OCSPCertStatus.GOOD:
        logging.info('Certificate OCSP revocation check returned status: GOOD.')
        return (False, None)
    elif cert_status == ocsp.OCSPCertStatus.REVOKED:
        try:
            reason = matched_single_resp.revocation_reason.name
        except Exception:
            reason = "UNSPECIFIED"
        logging.error(f'Certificate confirmed REVOKED via OCSP check due to: {reason}')
        return (True, reason)
    else: # UNKNOWN status - try next URL
        error_msg = 'Certificate OCSP revocation check returned status = UNKNOWN.'
        logging.error(error_msg)
        return (None, error_msg)

def extract_single_response_extensions(ocsp_resp_bytes, response_index):
    """
    Use asn1crypto to extract extensions from a specific SingleResponse.
    
    Args:
        ocsp_resp_bytes: Raw bytes of the OCSP response
        response_index: Index of the SingleResponse to extract extensions from
        
    Returns:
        list: List of extension dictionaries with 'oid', 'critical', and 'value'
    """
    from asn1crypto import ocsp as asn1_ocsp
    try:
        # Parse the OCSP response using asn1crypto
        ocsp_response = asn1_ocsp.OCSPResponse.load(ocsp_resp_bytes)
        # Check if response is successful
        if ocsp_response['response_status'].native != 'successful':
            logging.warning(f"OCSP response status: {ocsp_response['response_status'].native}")
            return []
        
        # Get the response bytes
        response_bytes = ocsp_response['response_bytes']
        if response_bytes['response_type'].native != 'basic_ocsp_response':
            logging.warning("Not a basic OCSP response")
            return []
        # Parse the BasicOCSPResponse
        basic_response = response_bytes['response'].parsed
        # Get the response data
        response_data = basic_response['tbs_response_data']
        responses = response_data['responses']
        
        if response_index >= len(responses):
            logging.error(f"Response index {response_index} out of range (max: {len(responses) - 1})")
            return []
        
        # Get the specific SingleResponse
        single_response = responses[response_index]
        
        # Extract extensions if present
        extensions_list = []
        if 'single_extensions' in single_response and single_response['single_extensions']:
            for extension in single_response['single_extensions']:
                ext_info = {
                    'oid': extension['extn_id'].dotted,
                    'oid_name': get_ocsp_oid_name(extension['extn_id'].dotted),
                    'critical': extension['critical'].native if extension['critical'] else False,
                    'value': extension['extn_value'].native
                }
                extensions_list.append(ext_info)
                
                logging.debug(f" - Extension OID:       {ext_info['oid']} ({ext_info['oid_name']})")
                logging.debug(f" - Extension Critical:  {ext_info['critical']}")
                logging.debug(f" - Extension Value:     {repr(ext_info['value'])}")
        else:
            logging.debug("No Extensions present in OCSP SingleResponse")
    except Exception as e:
        logging.warning(f"Error parsing OCSP extensions with asn1crypto: {e}")

def _check_crl(cert: x509.Certificate, crl_urls: list, issuer_cert: x509.Certificate, timeout: int) -> Tuple[Optional[bool], Optional[str]]:
    """
    Check certificate status via CRL.
    Returns (True, reason) if revoked, (False, None) if not revoked, (None, None) if error.
    """
    logging.warning(f"-----------------------------------Entering _check_crl()------------------------------------------")
    cert_serial = cert.serial_number
    logging.debug(f'Cert serial number: {cert_serial}')
    error_messages = []

    # Try each CRL URL
    for url in crl_urls:
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code != 200:
                continue
            
            # Try to parse as DER first, then PEM
            crl = None
            try:
                crl = x509.load_der_x509_crl(response.content)
                logging.debug(f'Successfully parsed DER-encoded CRL.')
            except Exception:
                try:
                    crl = x509.load_pem_x509_crl(response.content)
                    logging.debug(f'Successfully parsed PEM-encoded CRL.')
                except Exception:
                    error_msg = f'Unable to parse downloaded CRL {crl}'
                    error_messages.append(error_msg)
                    logging.debug(error_msg)
                    continue
            
            # Check if parsing succeeded & skip if not.
            if crl is None: continue
            
            # Check signature on CRL
            signature_verified = validate_crl_signature(crl, issuer_cert)
            if not signature_verified:
                error_msg = f'&emsp;&emsp;▶ Digitial signature verification on CRL failed.'
                error_messages.append(error_msg)
                logging.error(error_msg)
                continue
                #return (None, error_msg, None)

            # Check if CRL is current
            now = datetime.now(timezone.utc)
            if crl.next_update_utc and now > crl.next_update_utc:
                error_msg = f'CRL expired on {crl.next_update_utc.strftime("%Y-%m-%d")}.'
                logging.debug(f'{error_msg}  Trying next CRL (if present)...')
                error_messages.append(error_msg)
                continue
            
            # Check if certificate is in the revoked list
            try:
                logging.debug(f'Checking CRL for serial number: {cert_serial}')
                revoked_cert = crl.get_revoked_certificate_by_serial_number(cert_serial)
                
                if revoked_cert is not None:
                    # Get revocation reason from extensions
                    reason = _get_crl_revocation_reason(revoked_cert)
                    return (True, reason, None)
                else:
                    # Cert not present in CRL
                    logging.debug('Cert not present in CRL')
                    return (False, None, None)
            except Exception as e:
                # If we can't check the serial, continue to next CRL
                error_msg = f'Encountered exception: {e}'
                logging.debug(error_msg)
                error_messages.append(error_msg)
                continue
                
        except Exception as e:
            # Log but continue to next URL
            error_msg = f'Encountered catch-all exception: {e}'
            logging.debug(error_msg)
            error_messages.append(error_msg)
            continue
    
    logging.debug('Unable to check revocation via CRL.')
    return (None, None, error_messages)

def validate_ocsp_signature(ocsp_resp: ocsp.OCSPResponse, cert_chain: list[x509.Certificate], issuer_cert: x509.Certificate) -> bool:
        """Validate the OCSP response signature against the certificate chain"""

        # Check if the OCSP response includes certificates (for delegated responders)
        candidate_responder_certs = []
        if ocsp_resp.certificates:
            # Try to validate using the certificates included in the OCSP response
            for ocsp_cert in ocsp_resp.certificates:
                logging.info(f'Found delegated OCSP Responder cert embedded in OCSP response:')
                logging.info(f'   - Subject: {ocsp_cert.subject.rfc4514_string()}')
                logging.info(f'   - Issuer:  {ocsp_cert.issuer.rfc4514_string()}')
                logging.info(f'   - Serial:  {ocsp_cert.serial_number}')
                logging.info(f'   - Digest:  {ocsp_cert.fingerprint(hashes.SHA256()).hex()}')
                #logging.debug(f'Delegated OCSP Responder Cert PEM:\n{ (ocsp_cert.public_bytes(serialization.Encoding.PEM)).decode()  }')
                
                try:
                    ocsp_cert.verify_directly_issued_by(issuer_cert)
                except Exception as e:
                    logging.debug(f"OCSP responder cert not issued by CA: {e}")
                    continue
                
                # Delegated responders MUST have id-kp-OCSPSigning EKU per RFC6960
                try:
                    eku = ocsp_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
                    if ExtendedKeyUsageOID.OCSP_SIGNING in eku:
                        logging.info("   - Cert has the necessary OCSP Responder Signing Extended EKU (OID 1.3.6.1.5.5.7.3.9).")
                        candidate_responder_certs.append(ocsp_cert)
                        has_ocsp_signing = True
                except x509.ExtensionNotFound:
                    logging.error("No Extended Key Usage extension found .")
                    continue
                except Exception as e:
                    # Encountered Cryptography bug while parsing OCSP responder cert EKU; check against raw DER bytes as interim workaround
                    logging.error(f'Encountered exception attempting to check EKUs for OCSP responder certificate: {e}')
                    logging.warning(f"Attempting to validate against raw DER data as a workaround to parsing bugs...")
                    try:
                        # Get the raw certificate DER
                        cert_der = ocsp_cert.public_bytes(serialization.Encoding.DER)

                        # OID for Extended Key Usage: 2.5.29.37
                        eku_oid = b'\x06\x03\x55\x1d\x25'
                        # OID for OCSP Signing: 1.3.6.1.5.5.7.3.9
                        ocsp_signing_oid = b'\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x09'
                        
                        # Check if both OIDs are present in the DER
                        if eku_oid in cert_der and ocsp_signing_oid in cert_der:
                            logging.info("Found OCSP_SIGNING EKU in raw DER")
                            #has_ocsp_signing = True
                            candidate_responder_certs.append(ocsp_cert)
                        else:
                            logging.warning("OCSP_SIGNING EKU not found in raw DER")
                    except Exception as e2:
                        logging.error(f"Failed to check raw DER: {e2}")
                        continue
                
                if not candidate_responder_certs:
                    logging.warning("OCSP cert issued by CA but missing OCSP_SIGNING EKU - invalid per RFC 6960")

        if candidate_responder_certs:
            logging.info("Found valid delegated OCSP responder certificate with OCSP_SIGNING EKU")
        else:
            logging.info('No [verified] delegated responder cert(s) found; attempting to use issuing CA certificate for OCSP signature verification.')
            logging.debug(f'Issuer CA cert subject: {issuer_cert.subject.rfc4514_string()}')
            logging.debug(f'Issuer CA cert digest:  {issuer_cert.fingerprint(hashes.SHA256()).hex()}')
            candidate_responder_certs = [issuer_cert]
                
        # Verify OCSP response signature
        verified = False
        data_to_verify = ocsp_resp.tbs_response_bytes  # raw signed bytes
        signature = ocsp_resp.signature
        signature_hash_algorithm = ocsp_resp.signature_hash_algorithm

        for responder_cert in candidate_responder_certs:
            pubkey = responder_cert.public_key()
            try:
                if isinstance(pubkey, rsa.RSAPublicKey):
                    logging.debug('Responder public key type: RSA')
                    pubkey.verify(signature, data_to_verify, padding.PKCS1v15(), signature_hash_algorithm)
                    verified = True
                elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                    logging.debug('Responder public key type: EC')
                    pubkey.verify(signature, data_to_verify, ec.ECDSA(signature_hash_algorithm))
                    verified = True
                elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                    logging.debug('Responder public key type: ed25519')
                    pubkey.verify(signature, data_to_verify)
                    verified = True
                else:
                    logging.error(f"Unsupported public key type: {type(pubkey)}")
                    continue
            except exceptions.InvalidSignature:
                logging.error(f'Signature could not be verified against the attempted responder public key.')
                continue
            
            if verified:
                logging.info(f"Verified digital signature on OCSP response; signed by: {responder_cert.subject.rfc4514_string()}")
                return True

        logging.error("Could not verify OCSP response signature against OCSP responder signing certificate(s).")
        return False                    

def validate_crl_signature(crl: x509.CertificateRevocationList, issuer_cert: x509.Certificate):
    """Validate the CRL signature against the issuer certificate
    
    Args:
        crl: cryptography.x509.CertificateRevocationList object
        issuer_cert: cryptography.x509.Certificate object (the CA cert)
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Check if the CRL is current
        now = datetime.now(timezone.utc)
        
        if crl.last_update_utc > now:
            logging.error("CRL last_update is in the future")
            return False
        
        if crl.next_update_utc and crl.next_update_utc < now:
            logging.error("CRL has expired (next_update passed)")
            # Don't return False - expired CRL is still valid, just stale
        
        # Check if CRL issuer matches the certificate issuer
        if crl.issuer != issuer_cert.subject:
            logging.warning("CRL  Issuer does not match certificate issuer")
            logging.warning(f"CRL  Issuer: {crl.issuer.rfc4514_string()}")
            logging.warning(f"Cert Issuer: {issuer_cert.subject.rfc4514_string()}")
            
            # Check Authority Key Identifier
            try:
                aki_ext = crl.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                crl_aki = aki_ext.value.key_identifier
                
                try:
                    issuer_ski_ext = issuer_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                    issuer_ski = issuer_ski_ext.value.key_identifier
                    
                    if crl_aki != issuer_ski:
                        logging.warning("CRL signed by different authority (delegated CRL signer)")
                        return False
                except x509.ExtensionNotFound:
                    logging.error("Issuer cert missing Subject Key Identifier")
                    return False
                    
            except x509.ExtensionNotFound:
                logging.error("CRL missing Authority Key Identifier")
                return False
        
        # Perform actual cryptographic signature verification
        try:
            public_key = issuer_cert.public_key()
            signature = crl.signature
            tbs_cert_list = crl.tbs_certlist_bytes
            
            # Get the signature algorithm
            sig_oid = crl.signature_algorithm_oid
            
            # Determine hash algorithm from signature OID
            hash_algorithm = get_hash_algorithm_from_oid(sig_oid)
            
            if hash_algorithm is None:
                logging.error(f"Unsupported signature algorithm: {sig_oid.dotted_string}")
                return False
            
            # Verify signature based on key type
            if isinstance(public_key, rsa.RSAPublicKey):
                # RSA signature verification
                try:
                    public_key.verify(signature, tbs_cert_list, padding.PKCS1v15(), hash_algorithm)
                    logging.info("CRL RSA signature verified successfully.")
                    return True
                except InvalidSignature:
                    logging.error("CRL RSA signature verification FAILED!")
                    return False
                    
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                # ECDSA signature verification
                try:
                    public_key.verify(signature, tbs_cert_list, ec.ECDSA(hash_algorithm))
                    logging.info("CRL ECDSA signature verified successfully")
                    return True
                except InvalidSignature:
                    logging.error("CRL ECDSA signature verification FAILED")
                    return False
                    
            elif isinstance(public_key, dsa.DSAPublicKey):
                # DSA signature verification
                try:
                    public_key.verify(
                        signature,
                        tbs_cert_list,
                        hash_algorithm
                    )
                    logging.info("CRL DSA signature verified successfully")
                    return True
                except InvalidSignature:
                    logging.error("CRL DSA signature verification FAILED")
                    return False
                    
            else:
                logging.warning(f"Unsupported public key type: {type(public_key)}")
                return False
                
        except Exception as e:
            logging.error(f"Error during CRL signature verification: {e}")
            return False
        
    except Exception as e:
        logging.error(f"Error validating CRL signature: {e}")
        return False
