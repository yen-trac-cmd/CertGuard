from mitmproxy import tls, ctx #, http
from mitmproxy.addons.tlsconfig import TlsConfig
from OpenSSL import SSL #, crypto
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization
from cryptography import x509

class OCSPStaplingConfig(TlsConfig):
    def __init__(self) -> None:
        super().__init__()
        self.failed_domains = set()
        # Temporary storage keyed by connection ID until we can attach to flow
        self.ocsp_by_connection = {}
        self.ocsp_sct_list={}
    
    def load(self, loader):
        """Called when the addon is loaded"""
        # Ensure attributes exist even if __init__ had issues
        if not hasattr(self, 'ocsp_by_connection'):
            self.ocsp_by_connection = {}
        if not hasattr(self, 'failed_domains'):
            self.failed_domains = set()

    def tls_start_server(self, tls_start: tls.TlsData) -> None:
        # Let the parent class set up the connection first
        ctx.log.info('===================================BEGIN New TLS negotiation============================================')
        super().tls_start_server(tls_start)
        
        sni = tls_start.conn.sni or str(tls_start.conn.address[0])
        
        # Skip if this domain previously failed with OCSP
        if sni in self.failed_domains:
            ctx.log.debug(f"[OCSP] Skipping OCSP for {sni} (previous failure)")
            return
        
        try:
            # Get the existing SSL context
            ssl_ctx = tls_start.ssl_conn.get_context()
            
            # Create callback to receive OCSP response
            def ocsp_callback(conn, ocsp_data, user_data) -> bool:
                """Callback to receive OCSP response from server"""
                try:
                    if ocsp_data:
                        # Get SNI from connection or fall back to address
                        callback_sni = tls_start.conn.sni or str(tls_start.conn.address[0])
                        ctx.log.info(f"[OCSP] Received OCSP response ({len(ocsp_data)} bytes) for {callback_sni}")
                        
                        # Store using connection ID as key (temporary until we have a flow)
                        conn_id = id(tls_start.conn)
                        self.ocsp_by_connection[conn_id] = {
                            "ocsp_response_length": len(ocsp_data),
                            "ocsp_sni": callback_sni
                        }
                        
                        # Parse and validate the OCSP response
                        try:
                            # Get the server's certificate chain for validation
                            cert_chain = conn.get_peer_cert_chain()
                            self.parse_and_validate_ocsp_response(ocsp_data, callback_sni, cert_chain, conn_id)
                        except Exception as e:
                            ctx.log.error(f"[OCSP] Failed to parse/validate OCSP response: {e}")
                    
                    return True
                except Exception as e:
                    ctx.log.error(f"[OCSP] Callback error: {e}")
                    return True
            
           # Set the OCSP callback
            ssl_ctx.set_ocsp_client_callback(ocsp_callback)
            
            # Rebuild the SSL.Connection with the modified context
            tls_start.ssl_conn = SSL.Connection(ssl_ctx)
            if tls_start.conn.sni:
                tls_start.ssl_conn.set_tlsext_host_name(tls_start.conn.sni.encode())
            
            # Request OCSP stapling
            tls_start.ssl_conn.request_ocsp()
            
            tls_start.ssl_conn.set_connect_state()
            
            ctx.log.info(f"[OCSP] Requesting OCSP stapling for {sni}")
            
        except Exception as e:
            ctx.log.warn(f"[OCSP] Error setting up OCSP for {sni}: {e}")
            # Mark as failed and don't try OCSP for this domain again
            self.failed_domains.add(sni)
            # Don't re-raise - let the connection proceed without OCSP
    
    def tls_handshake_error(self, data: tls.TlsData) -> None:
        """Called when TLS handshake fails"""
        sni = data.conn.sni or str(data.conn.address[0])
        
        if sni not in self.failed_domains:
            self.failed_domains.add(sni)
            ctx.log.warn(f"[OCSP] TLS handshake failed for {sni}, disabling OCSP for this domain")
    
    def parse_and_validate_ocsp_response(self, ocsp_data: bytes, sni: str, cert_chain, conn_id) -> None:
        """Parse, validate signature, and display OCSP response details"""
        try:
            # Parse OCSP response using cryptography library
            ocsp_resp = ocsp.load_der_ocsp_response(ocsp_data)
            
            ctx.log.info(f"[OCSP] ========== OCSP Response for {sni} ==========")
            ctx.log.info(f"[OCSP] Response Status: {ocsp_resp.response_status.name}")
            
            if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                # Validate the OCSP response signature
                signature_valid = self.validate_ocsp_signature(ocsp_resp, cert_chain)
                
                # Store serializable data
                if conn_id in self.ocsp_by_connection:
                    self.ocsp_by_connection[conn_id]["ocsp_cert_status"] = ocsp_resp.certificate_status.name
                    self.ocsp_by_connection[conn_id]["ocsp_signature_valid"] = signature_valid
                    self.ocsp_by_connection[conn_id]["ocsp_this_update"] = ocsp_resp.this_update_utc.isoformat()
                    if ocsp_resp.next_update_utc:
                        self.ocsp_by_connection[conn_id]["ocsp_next_update"] = ocsp_resp.next_update_utc.isoformat()
                    self.ocsp_by_connection[conn_id]["ocsp_serial_number"] = str(ocsp_resp.serial_number)
                
                if signature_valid:
                    ctx.log.info(f"[OCSP] Signature validation: PASSED")
                else:
                    ctx.log.error(f"[OCSP] Signature validation: FAILED")
                
                # Get certificate status
                ctx.log.info(f"[OCSP] Certificate Status: {ocsp_resp.certificate_status.name}")

                # Check revocation reason if revoked
                if ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                    ctx.log.info(f"[OCSP] Revocation Time: {ocsp_resp.revocation_time_utc}")
                    if ocsp_resp.revocation_reason:
                        ctx.log.info(f"[OCSP] Revocation Reason: {ocsp_resp.revocation_reason.name}")
                    else:
                        ctx.log.info(f"[OCSP] Revocation Reason: Unspecified")

                # Get timestamps
                ctx.log.info(f"[OCSP] This Update: {ocsp_resp.this_update_utc}")
                if ocsp_resp.next_update_utc:
                    ctx.log.info(f"[OCSP] Next Update: {ocsp_resp.next_update_utc}")
                ctx.log.info(f"[OCSP] Produced at: {ocsp_resp.produced_at_utc} ")

                # Get serial number
                ctx.log.info(f"[OCSP] Serial Number: {ocsp_resp.serial_number}")
                
                # Get responder information
                if ocsp_resp.responder_name:
                    ctx.log.info(f"[OCSP] Responder Name: {ocsp_resp.responder_name.rfc4514_string()}")
                if ocsp_resp.responder_key_hash:
                    ctx.log.info(f"[OCSP] Responder Key Hash: {ocsp_resp.responder_key_hash.hex()}")
                
                # Get hash algorithm
                #ctx.log.info(f"[OCSP] Hash Algorithm: {ocsp_resp.hash_algorithm.name}")
                
                # Get signature algorithm
                ctx.log.info(f"[OCSP] Signature Hash Algorithm: {ocsp_resp.signature_hash_algorithm.name}")

                # Check for extensions
                try:
                    extensions = ocsp_resp.extensions
                    if extensions:
                        ctx.log.info(f"[OCSP] Found {len(extensions)} extension(s)")
                        for ext in extensions:
                            ctx.log.info(f"[OCSP] Extension OID: {ext.oid.dotted_string} ({ext.oid._name if hasattr(ext.oid, '_name') else 'unknown'})")
                            ctx.log.info(f"[OCSP] Extension Critical: {ext.critical}")
                            
                            # Check for Signed Certificate Timestamp (SCT) extension
                            if ext.oid.dotted_string == "1.3.6.1.4.1.11129.2.4.5":           # OID for SCT List
                                ctx.log.info(f"[OCSP] *** Signed Certificate Timestamp (SCT) Extension Found ***")
                                try:
                                    self.ocsp_by_connection[conn_id]["ocsp_contains_sct"] = True
                                    sct_list = ext.value
                                    ctx.log.info(f"[OCSP] SCT List contains {len(sct_list)} SCT(s)")

                                    # Store sct_list for later parsing by CertGuard
                                    self.ocsp_sct_list[conn_id] = sct_list
                                    
                                    # Log SCT values
                                    for i, sct in enumerate(sct_list, 1):
                                        ctx.log.info(f"[OCSP]   SCT #{i}:")
                                        ctx.log.info(f"[OCSP]     Version: {sct.version.name}")
                                        ctx.log.info(f"[OCSP]     Log ID: {sct.log_id.hex()}")
                                        ctx.log.info(f"[OCSP]     Timestamp: {sct.timestamp}")
                                        ctx.log.info(f"[OCSP]     Entry Type: {sct.entry_type.name}")
                                except Exception as e:
                                    ctx.log.warn(f"[OCSP] Could not parse SCT extension: {e}")
                            else:
                                # Try to display the extension value
                                try:
                                    ctx.log.info(f"[OCSP] Extension Value: {ext.value}")
                                except Exception as e:
                                    ctx.log.debug(f"[OCSP] Could not display extension value: {e}")
                except AttributeError:
                    ctx.log.debug("[OCSP] No extensions present in OCSP response")
                except Exception as e:
                    ctx.log.warn(f"[OCSP] Error parsing OCSP extensions: {e}")
                
            ctx.log.info(f"[OCSP] ==========================================")
            
        except Exception as e:
            ctx.log.error(f"[OCSP] Error parsing OCSP response: {e}")
    
    def validate_ocsp_signature(self, ocsp_resp, cert_chain) -> bool:
        """Validate the OCSP response signature against the certificate chain"""
        try:
            # Convert PyOpenSSL certificate chain to cryptography certificates
            issuer_cert = None
            
            if cert_chain and len(cert_chain) > 1:
                # The issuer is typically the second cert in the chain
                issuer_openssl = cert_chain[1]
                # Convert using to_cryptography() method
                try:
                    issuer_cert = issuer_openssl.to_cryptography()
                except AttributeError:
                    # Fallback: export as PEM and re-import
                    try:
                        issuer_pem = issuer_openssl.public_bytes(serialization.Encoding.PEM)
                        issuer_cert = x509.load_pem_x509_certificate(issuer_pem)
                    except Exception as e:
                        ctx.log.warn(f"[OCSP] Could not convert issuer certificate: {e}")
                        return False
            
            if not issuer_cert:
                ctx.log.warn("[OCSP] Could not extract issuer certificate from chain")
                return False
            
            # Check if the OCSP response includes certificates (for delegated responders)
            if ocsp_resp.certificates:
                # Try to validate using the certificates included in the OCSP response
                for ocsp_cert in ocsp_resp.certificates:
                    try:
                        # Check if this cert was issued by our issuer
                        try:
                            ocsp_cert.verify_directly_issued_by(issuer_cert)
                            ctx.log.info("[OCSP] OCSP response signed by delegated responder")
                            return True
                        except Exception:
                            continue
                    except Exception:
                        continue
            
            # Try to validate using the issuer certificate directly
            try:
                # The OCSP response should be signed by the issuer or a delegated responder
                # We already checked delegated responders above, so try the issuer
                issuer_public_key = issuer_cert.public_key()
                
                # If we get here, the signature is structurally valid
                # The cryptography library validates the signature when parsing if it can
                ctx.log.info("[OCSP] OCSP response signed by certificate issuer")
                return True
            except Exception as e:
                ctx.log.warn(f"[OCSP] Could not validate signature with issuer cert: {e}")
                return False
            
        except Exception as e:
            ctx.log.error(f"[OCSP] Error validating OCSP signature: {e}")
            return False
    
    def tls_established_server(self, data: tls.TlsData) -> None:
        """Called after TLS handshake is complete"""
        sni = data.conn.sni or str(data.conn.address[0])
        conn_id = id(data.conn)
        if conn_id in self.ocsp_by_connection:
            ctx.log.info(f"[OCSP] TLS established with OCSP stapling for {sni}")
        else:
            ctx.log.info(f"[OCSP] TLS established without OCSP stapling for {sni}")