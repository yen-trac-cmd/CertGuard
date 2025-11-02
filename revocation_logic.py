from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
from requests.exceptions import RequestException
from typing import Tuple, Optional
from urllib3.exceptions import NameResolutionError
import logging
import requests

def check_cert_chain_revocation(cert_chain: list[x509.Certificate], skip_leaf: bool, timeout: int = 10) -> Tuple[bool, str, Optional[int], Optional[str], Optional[str]]:
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
        
        is_revoked, error, reason, method = check_cert_revocation(cert, issuer, cert_chain, timeout)
        
        if is_revoked:
            revoked = True
            logging.error(f'Cert #{i} ({cn}) is revoked per {method}. \nReason: {reason}')
            all_errors.append(f"<br>&emsp;&emsp;▶ Cert #{i} (<code>{cn}</code>) is revoked per {method}<br>&emsp;&emsp;<b>Reason:</b> {reason}")
        
        if error:
            #cn = ""
            logging.error(f'Error encountered checking cert #{i} ({cn}): {error}')
            all_errors.append(f"⚠️ Error encountered checking cert #{i} (<code>{cn}</code>):<br>&emsp;&emsp;▶ {error}")
    
    # If we checked all certs and none were revoked
    if not all_errors and not revoked:
        return (False, None)

    error_msg = "<br>".join(all_errors)
    if revoked:
        return (True, error_msg)
    else:
        # If we had errors but no confirmed revocations
        return (False, error_msg)

def check_cert_revocation(cert: x509.Certificate, issuer_cert: x509.Certificate, cert_chain: list[x509.Certificate], timeout: int = 10) -> Tuple[bool, str, Optional[str], Optional[str]]:
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
    logging.warning(f"-----------------------------------Entering check_cert_revocation()--------------------------------------------------")
    logging.info(f"Checking revocation for {cert.subject.rfc4514_string()}")
    crl_result = None
    ocsp_result = None
    errors = []
    
    # Try OCSP first
    try:
        ocsp_urls = _get_ocsp_urls(cert)
        if ocsp_urls: #and issuer_cert:
            ocsp_result, return_msg = _check_ocsp(cert, issuer_cert, cert_chain, ocsp_urls, timeout)
            if ocsp_result is True:  # Explicitly revoked
                return (True, "", return_msg, "OCSP")
            elif ocsp_result is False:  # Explicitly not revoked
                return (False, "", None, None)
            else:
                errors.append(f"OCSP check returned: {return_msg}")
        #elif ocsp_urls and not issuer_cert:
        #    errors.append("OCSP URL found but no issuer certificate provided")
    except Exception as e:
        errors.append(f"OCSP check failed: {str(e)}")
    
    # Try CRL as fallback
    logging.info('Unable to check revocation via OCSP; falling back to CRL (if CDP present).')
    try:
        crl_urls = _get_crl_urls(cert)
        if crl_urls:
            crl_result, crl_reason = _check_crl(cert, crl_urls, issuer_cert, timeout)
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
    logging.warning(f"-----------------------------------Entering _get_crl_urls()--------------------------------------------------")
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

def _check_ocsp(cert: x509.Certificate, issuer_cert: x509.Certificate, cert_chain: list[x509.Certificate], ocsp_urls: list, timeout: int ) -> Tuple[Optional[bool], Optional[str]]:
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
    exception_messages = []
    for url in ocsp_urls:
        #try:
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
                logging.error(exception_msg + f':\n --> {e}')
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

            try:
                ocsp_resp = ocsp.load_der_ocsp_response(response.content)
            except ValueError as e:
                exception_msg = f"Error parsing OCSP response: {e}"
                logging.error(exception_msg)
                exception_messages.append(exception_msg)
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
                for ext in ocsp_resp.single_extensions:
                    logging.debug(f"  - {ext.oid._name}: {ext.value}")
            else:
                logging.debug(" - OCSP Extensions:     (None found)")

            signature_verified = validate_ocsp_signature(ocsp_resp, cert_chain, issuer_cert)
            if not signature_verified:
                logging.error(f'Digitial signature verification on OCSP response failed.')
                continue

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
            
        #except Exception as e:
        #    logging.error(f'Encountered exception attempting to query OCSP: {e}')
        #    continue
    return (None, "\n".join(exception_messages))
    
def _check_crl(cert: x509.Certificate, crl_urls: list, issuer_cert: x509.Certificate, timeout: int) -> Tuple[Optional[bool], Optional[str]]:
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
            
            # Check signature on CRL
            signature_valid = validate_crl_signature(crl, issuer_cert)

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

def validate_ocsp_signature(ocsp_resp: ocsp.OCSPResponse, cert_chain, issuer_cert: x509.Certificate = None) -> bool:
        """Validate the OCSP response signature against the certificate chain"""
        try:
            if issuer_cert:
                pass
            else:
                # Convert PyOpenSSL certificate chain to cryptography certificates 
                # Only applicable for stapled OCSP check called from tls_extensions module
                issuer_cert = None
                if cert_chain and len(cert_chain) > 1:
                    issuer_openssl = cert_chain[1]
                    # Convert to x509.Certificate object
                    try:
                        issuer_cert = issuer_openssl.to_cryptography()
                    except AttributeError:
                        # Fallback: export as PEM and re-import
                        try:
                            issuer_pem = issuer_openssl.public_bytes(serialization.Encoding.PEM)
                            issuer_cert = x509.load_pem_x509_certificate(issuer_pem)
                        except Exception as e:
                            logging.warning(f"Could not convert issuer certificate: {e}")
                            return False
            
            if not issuer_cert:
                logging.warning("Could not extract issuer certificate from chain")
                return False
            
            candidate_responder_certs = []

            # Check if the OCSP response includes certificates (for delegated responders)
            if ocsp_resp.certificates:
                # Try to validate using the certificates included in the OCSP response
                for ocsp_cert in ocsp_resp.certificates:
                    logging.info(f'Found embedded certificate in OCSP response:')
                    logging.info(f'   - Subject: {ocsp_cert.subject.rfc4514_string()}')
                    logging.info(f'   - Issuer:  {ocsp_cert.issuer.rfc4514_string()}')

                    # Check for delegated responder use
                    try:
                        eku = ocsp_cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE).value
                        if x509.ExtendedKeyUsageOID.OCSP_SIGNING in eku:
                            logging.info("   - Cert has the necessary OCSP responder Extended Key Usage (EKU).")
                            candidate_responder_certs.append(ocsp_cert)
                        else:
                            logging.error("Embedded cert not marked for OCSP signing.")
                    except x509.ExtensionNotFound:
                        logging.error("No Extended Key Usage extension found.")
            
            if not candidate_responder_certs:
                logging.info('No delegated responder cert(s) found; using issuing CA certificate for OCSP signature verification.')
                candidate_responder_certs = [issuer_cert]
                    
            # Verify OCSP response signature
            data_to_verify = ocsp_resp.tbs_response_bytes  # raw signed bytes
            signature = ocsp_resp.signature
            signature_hash_algorithm = ocsp_resp.signature_hash_algorithm

            for responder_cert in candidate_responder_certs:
                pubkey = responder_cert.public_key()
                
                try:
                    if isinstance(pubkey, rsa.RSAPublicKey):
                        pubkey.verify(signature, data_to_verify, padding.PKCS1v15(), signature_hash_algorithm)
                    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                        pubkey.verify(signature, data_to_verify, ec.ECDSA(signature_hash_algorithm))
                    elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                        pubkey.verify(signature, data_to_verify)
                    else:
                        logging.error(f"Unsupported public key type: {type(pubkey)}")
                        continue
            
                    # If reach here, validation for one of the methods above was successful.
                    logging.info(f"Verified digital signature on OCSP response; signed by: {responder_cert.subject.rfc4514_string()}")
                    return True
                except InvalidSignature:
                    logging.error(f"OCSP response digital signature verification failed with {responder_cert.subject.rfc4514_string()}: {e}")
                    continue
                except Exception as e:
                    logging.error(f'Unexpected exception encountered while attempting to verify digital signature: {e}')
                    continue
            
            logging.error("All candidate certificates failed to verify OCSP response signature.")
            return False                    

        except Exception as e:
            logging.error(f"Error validating OCSP signature: {e}")
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
            logging.error("[Validation] CRL last_update is in the future")
            return False
        
        if crl.next_update_utc and crl.next_update_utc < now:
            logging.error("[Validation] CRL has expired (next_update passed)")
            # Don't return False - expired CRL is still valid, just stale
        
                   # Check if CRL issuer matches the certificate issuer
        if crl.issuer != issuer_cert.subject:
            logging.warning("[Validation] CRL issuer does not match certificate issuer")
            logging.warning(f"[Validation] CRL Issuer: {crl.issuer.rfc4514_string()}")
            logging.warning(f"[Validation] Cert Issuer: {issuer_cert.subject.rfc4514_string()}")
            
            # Check Authority Key Identifier
            try:
                aki_ext = crl.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
                )
                crl_aki = aki_ext.value.key_identifier
                
                try:
                    issuer_ski_ext = issuer_cert.extensions.get_extension_for_oid(
                        x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
                    )
                    issuer_ski = issuer_ski_ext.value.key_identifier
                    
                    if crl_aki != issuer_ski:
                        logging.warning("[Validation] CRL signed by different authority (delegated CRL signer)")
                        return False
                except x509.ExtensionNotFound:
                    logging.error("[Validation] Issuer cert missing Subject Key Identifier")
                    return False
                    
            except x509.ExtensionNotFound:
                logging.error("[Validation] CRL missing Authority Key Identifier")
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
                logging.error(f"[Validation] Unsupported signature algorithm: {sig_oid.dotted_string}")
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
                    logging.info("[Validation] ✓ CRL DSA signature verified successfully")
                    return True
                except InvalidSignature:
                    logging.error("[Validation] ✗ CRL DSA signature verification FAILED")
                    return False
                    
            else:
                logging.warning(f"[Validation] Unsupported public key type: {type(public_key)}")
                return False
                
        except Exception as e:
            logging.error(f"[Validation] Error during CRL signature verification: {e}")
            return False
        
    except Exception as e:
        logging.error(f"[Validation] Error validating CRL signature: {e}")
        return False

def get_hash_algorithm_from_oid(sig_oid):
    """Map signature algorithm OID to hash algorithm"""
    # Common signature algorithm OIDs
    oid_to_hash = {
        # RSA with SHA-256
        x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256: hashes.SHA256(),
        # RSA with SHA-384
        x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA384: hashes.SHA384(),
        # RSA with SHA-512
        x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512: hashes.SHA512(),
        # RSA with SHA-1 (deprecated but still used)
        x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA1: hashes.SHA1(),
        # ECDSA with SHA-256
        x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256: hashes.SHA256(),
        # ECDSA with SHA-384
        x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA384: hashes.SHA384(),
        # ECDSA with SHA-512
        x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA512: hashes.SHA512(),
        # DSA with SHA-256
        x509.oid.SignatureAlgorithmOID.DSA_WITH_SHA256: hashes.SHA256(),
    }
    
    return oid_to_hash.get(sig_oid)
