import requests
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
import logging
from typing import Tuple, Optional

def check_cert_chain_revocation(cert_chain: list, skip_leaf: bool, timeout: int = 10) -> Tuple[bool, str, Optional[int], Optional[str], Optional[str]]:
    """
    Check if any certificate in a chain has been revoked using CRL and/or OCSP.
    
    Args:
        cert_chain: List of x509.Certificate objects, ordered from leaf to root
                   [leaf_cert, intermediate_cert(s), root_cert]
        timeout: Request timeout in seconds (default: 10)
    
    Returns:
        Tuple of (is_revoked: bool, revocation_reasons: Optional[str], error_messages: str)
        - (True, revocation_reasons, error_messages) if any cert is revoked
        - (False, None, None) if all certificates are confirmed valid
        - (False, None, error_messages) if checks failed
    """
    logging.warning(f"-----------------------------------Entering check_cert_chain_revocation()--------------------------------------------------")
    if not cert_chain or len(cert_chain) == 0:
        return (False, "Empty certificate chain provided")
    
    all_errors = []
    
    # Check each certificate in the chain (except root, which is self-signed)
    revoked = False

    for i in range(len(cert_chain) - 1):
        cert = cert_chain[i]
        issuer = cert_chain[i + 1] if i + 1 < len(cert_chain) else None

        # Get certificate common name for logging messages
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = ""
        
        if skip_leaf and i == 0:
            logging.debug(f"Valid stapled OCSP response for {cn} found; skipping further revocation checks for leaf cert.")
            continue
        #cn = ""
        
        is_revoked, error, reason, method = check_cert_revocation(cert, issuer, timeout)
        
        if is_revoked:
            revoked = True
            logging.error(f'Cert {i} ({cn}) is revoked per {method}. \nReason: {reason}')
            all_errors.append(f"<br>&emsp;&emsp;▶ Cert {i} (<code>{cn}</code>) is revoked per {method}<br>&emsp;&emsp;<b>Reason:</b> {reason}")
        
        if error:
            #cn = ""
            logging.error(f'Error encountered checking cert {i} ({cn}): {error}')
            all_errors.append(f"⚠️ Error encountered checking cert {i} ({cn}): {error}")
    
    # If we checked all certs and none were revoked
    if not all_errors and not revoked:
        return (False, None)

    error_msg = "<br>".join(all_errors)
    if revoked:
        return (True, error_msg)
    else:
        # If we had errors but no confirmed revocations
        return (False, error_msg)

def check_cert_revocation(cert: x509.Certificate, issuer_cert: Optional[x509.Certificate] = None, timeout: int = 10) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """
    Check if a certificate has been revoked using CRL and/or OCSP.
    
    Args:
        cert: The x509.Certificate object to check
        issuer_cert: The issuer's certificate (required for OCSP)
        timeout: Request timeout in seconds (default: 10)
    
    Returns:
        Tuple of (is_revoked: bool, error_message: str, revocation_reason: Optional[str], method: Optional[str])
        - (True, "", "reason_code", "CRL/OCSP") if certificate is confirmed revoked
        - (False, "", None, None) if certificate is confirmed valid
        - (False, "error message", None, None) if check failed
    """
    logging.warning(f"-----------------------------------Entering check_cert_revocation()--------------------------------------------------")
    logging.info(f"Checking revocation for {cert.subject.rfc4514_string()}")
    crl_result = None
    ocsp_result = None
    revocation_reason = None
    errors = []

    # Try OCSP first
    try:
        ocsp_urls = _get_ocsp_urls(cert)
        if ocsp_urls and issuer_cert:
            ocsp_result, ocsp_reason = _check_ocsp(cert, issuer_cert, ocsp_urls, timeout)
            if ocsp_result is True:  # Explicitly revoked
                return (True, "", ocsp_reason, "OCSP")
            elif ocsp_result is False:  # Explicitly not revoked
                return (False, "", None, None)
            else:
                errors.append("OCSP check returned None")
        elif ocsp_urls and not issuer_cert:
            errors.append("OCSP URL found but no issuer certificate provided")
    except Exception as e:
        errors.append(f"OCSP check failed: {str(e)}")

    
    # Try CRL as fallback
    try:
        crl_urls = _get_crl_urls(cert)
        if crl_urls:
            crl_result, crl_reason = _check_crl(cert, crl_urls, timeout)
            if crl_result:  # Explicitly revoked
                return (True, "", crl_reason, "CRL")
            elif not crl_result: 
                return (False, "", None, None)
            else:
                errors.append("Encountered error in _check_crl(); CRL check returned None")
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
            logging.error(f"AttributeError accessing reason: {e}, reason_ext type: {type(reason_ext) if 'reason_ext' in locals() else 'N/A'}, value type: {type(reason_value) if 'reason_value' in locals() else 'N/A'}")
            return "UNSPECIFIED"
        
    except Exception as e:
        # Unexpected error, but return unspecified rather than failing
        logging.error(f"Unexpected error in _get_crl_revocation_reason: {e}")
        return "UNSPECIFIED"

def _get_ocsp_revocation_reason(ocsp_resp) -> Optional[str]:
    """Extract revocation reason from an OCSP response."""
    try:
        # OCSP responses may include revocation reason in extensions
        if hasattr(ocsp_resp, 'revocation_reason') and ocsp_resp.revocation_reason:
            return ocsp_resp.revocation_reason.name
        return "UNSPECIFIED"
    except Exception:
        return None

def _get_ocsp_urls(cert: x509.Certificate) -> list:
    """Extract OCSP URLs from certificate's Authority Information Access extension."""
    try:
        aia = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
        
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
    try:
        crl_dp = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
        
        urls = []
        for dp in crl_dp:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
        logging.debug(f'Extracted CRL Distribution Point (CDP) server(s) from cert: {urls}')
        return urls
    except x509.ExtensionNotFound:
        return []

def _check_ocsp(cert: x509.Certificate, issuer_cert: x509.Certificate, ocsp_urls: list, timeout: int ) -> Tuple[Optional[bool], Optional[str]]:
    """
    Check certificate status via OCSP.
    Returns (True, reason) if revoked, (False, None) if good, (None, None) if unknown/error.
    """
    logging.warning(f"-----------------------------------Entering _check_ocsp()--------------------------------------------------")
    # Build OCSP request
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1()) 
    req = builder.build()
    req_data = req.public_bytes(serialization.Encoding.DER)
    

    # Try each OCSP URL
    for url in ocsp_urls:
        try:
            headers = {
                'Content-Type': 'application/ocsp-request',
                'Accept': 'application/ocsp-response'
            }
            
            logging.debug(f'Querying OCSP server {url} for cert serial number {cert.serial_number}')
            response = requests.post(url, data=req_data, headers=headers, timeout=timeout)
            
            if response.status_code != 200:
                logging.error(f'Received HTTP response code {response.status_code} querying OCSP server; skipping server.')
                continue

            try:
                ocsp_resp = ocsp.load_der_ocsp_response(response.content)
            except ValueError as e:
                logging.error(f"Error parsing OCSP response: {e}")
                continue
           
            if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                logging.debug("The OCSP request was successful.")
            elif ocsp_resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
                logging.error(f"The OCSP responder is unauthorized to respond for check against {cert.subject.rfc4514_string()}; skipping server.")
                continue
            elif ocsp_resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST:
                logging.error("The OCSP request was malformed; skipping server.")
                continue
            else:
                logging.error(f"A non-successful status was received: {ocsp_resp.response_status.name}; skipping server.")
                continue
            
            # Log info about cert being checked & OCSP response data for debugging purposes
            logging.debug("OCSP Response Details:")
            for single_resp in ocsp_resp.responses:
                logging.debug(" Single Response")
                logging.debug(f" - Cert Serial Number:  {single_resp.serial_number}")
                logging.debug(f" - Serial Number (Hex): {hex(single_resp.serial_number)}")
                logging.debug(f" - Certificate Status:  {single_resp.certificate_status.name}")
                logging.debug(f" - This Update:         {single_resp.this_update_utc}")
                logging.debug(f" - Next Update:         {single_resp.next_update_utc}")
                
                if single_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                    logging.debug(f" - Revocation Time:     {single_resp.revocation_time_utc}")
                    if single_resp.revocation_reason:
                        logging.debug(f" - Revocation Reason:   {single_resp.revocation_reason}")
                    else:
                        logging.debug(" - Revocation Reason:   Unspecified")

            # Log response metadata
            if ocsp_resp.responder_key_hash:
                logging.debug(f" - Responder Key Hash:  {ocsp_resp.responder_key_hash.hex()}")
            if ocsp_resp.responder_name:
                logging.debug(f" - Responder Name:      {ocsp_resp.responder_name}")
            logging.debug(f" - Produced At:         {ocsp_resp.produced_at_utc}")
            logging.debug(f" - Signature Hash Algo: {ocsp_resp.signature_hash_algorithm.name}")

            
            # Log any extensions
            if ocsp_resp.extensions:
                logging.debug(" Extensions:")
                for ext in ocsp_resp.extensions:
                    logging.debug(f"  - {ext.oid._name}: {ext.value}")
            else:
                logging.debug(" - OCSP Extensions:     (None found)")

            cert_status = ocsp_resp.certificate_status
            if cert_status == ocsp.OCSPCertStatus.GOOD:
                logging.info('Certificate OCSP revocation check returned status: GOOD.')
                return (False, None)
            elif cert_status == ocsp.OCSPCertStatus.REVOKED:
                # Try to get revocation reason
                reason = _get_ocsp_revocation_reason(ocsp_resp)
                logging.error(f'Certificate confirmed REVOKED via OCSP check due to: {reason}')
                return (True, reason)
            else: # UNKNOWN status - try next URL
                logging.error('Certificate OCSP revocation check returned status = UNKNOWN.')
                continue
            
        except Exception as e:
            logging.error(f'Encountered exception attempting to query OCSP: {e}')
            continue
    return (None, None)

def _check_crl(cert: x509.Certificate, crl_urls: list, timeout: int) -> Tuple[Optional[bool], Optional[str]]:
    """
    Check certificate status via CRL.
    Returns (True, reason) if revoked, (False, None) if not revoked, (None, None) if error.
    """
    logging.warning(f"-----------------------------------Entering _check_crl()--------------------------------------------------")
    cert_serial = cert.serial_number
    logging.debug(f'Cert serial number: {cert_serial}')

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
                    logging.debug(f'Unable to parse downloaded CRL {crl}')
                    continue
            
            # Check if parsing succeeded & skip if not.
            if crl is None:
                continue
            
            # Check if CRL is current
            now = datetime.now(timezone.utc)
            if crl.next_update_utc and now > crl.next_update_utc:
                logging.debug('CRL is expired; trying next one (if present)...')
                continue
            
            # Check if certificate is in the revoked list
            try:
                logging.debug(f'Checking CRL for serial number: {cert_serial}')
                revoked_cert = crl.get_revoked_certificate_by_serial_number(cert_serial)
                
                if revoked_cert is not None:
                    # Get revocation reason from extensions
                    reason = _get_crl_revocation_reason(revoked_cert)
                    return (True, reason)
                else:
                    # Cert not present in CRL
                    logging.debug('Cert not present in CRL')
                    return (False, None)
            except Exception as e:
                # If we can't check the serial, continue to next CRL
                logging.debug(f'Encountered exception: {e}')
                continue
                
        except Exception as e:
            # Log but continue to next URL
            logging.debug(f'Encountered last-catch exception: {e}')
            continue
    
    logging.debug('Catch-all return; returning None, None.')
    return (None, None)