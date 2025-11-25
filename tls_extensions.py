import logging
from certguard_config import Config
from mitmproxy import tls
from mitmproxy.addons.tlsconfig import TlsConfig
from OpenSSL import SSL
from cryptography.x509 import ocsp, UnrecognizedExtension, Certificate
from chain_builder import normalize_chain
from revocation_logic import validate_ocsp_signature

config = Config()

class OCSPStaplingConfig(TlsConfig):
    def __init__(self) -> None:
        super().__init__()
        self.failed_domains = set()
        
        # Temporary storage keyed by connection ID until attached to flow
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
        if not config.revocation_checks:
            return
        
        logging.info('===================================BEGIN New TLS negotiation======================================')
        
        # Let the parent class set up the connection first
        super().tls_start_server(tls_start)
        
        sni = tls_start.conn.sni or str(tls_start.conn.address[0])
        
        # Skip if this domain previously failed with OCSP
        if sni in self.failed_domains:
            logging.debug(f"[OCSP] Skipping OCSP for {sni} (previous failure)")
            return
        
        try:
            # Get the existing SSL context
            ssl_ctx = tls_start.ssl_conn.get_context()

            # Create callback to receive OCSP response
            def ocsp_callback(conn: SSL.Connection, ocsp_data, user_data) -> bool:
                """Callback to receive OCSP response from server"""
                try:
                    if ocsp_data:
                        # Get SNI from connection or fall back to address
                        callback_sni = tls_start.conn.sni or str(tls_start.conn.address[0])
                        logging.info(f"[OCSP] Received OCSP response ({len(ocsp_data)} bytes) for {callback_sni}")
                        
                        # Store using connection ID as key (temporary until we have a flow)
                        conn_id = id(tls_start.conn)
                        self.ocsp_by_connection[conn_id] = {
                            "ocsp_response_length": len(ocsp_data),
                            "ocsp_sni": callback_sni
                        }
                        
                        # Parse and validate the OCSP response
                        try:
                            # Get the server's certificate chain for validation
                            cert_chain = conn.get_peer_cert_chain(as_cryptography=True)
                            cert_chain = normalize_chain(cert_chain)
                            self.parse_and_validate_ocsp_response(ocsp_data, cert_chain[0], conn_id)
                        except Exception as e:
                            logging.error(f"[OCSP] Failed to parse/validate OCSP response: {e}")
                    
                    return True
                except Exception as e:
                    logging.error(f"[OCSP] Callback error: {e}")
                    return True
            
           # Set the OCSP callback
            ssl_ctx.set_ocsp_client_callback(ocsp_callback)

            # Request OCSP stapling
            tls_start.ssl_conn.request_ocsp()
            logging.info(f"[OCSP] Requesting OCSP stapling for {sni}")
            
        except Exception as e:
            logging.warning(f"[OCSP] Error setting up OCSP for {sni}: {e}")
            # Mark as failed and don't try OCSP for this domain again
            self.failed_domains.add(sni)
    
    def tls_failed_server(self, data: tls.TlsData) -> None:
        """Called when TLS handshake fails"""
        sni = data.conn.sni or str(data.conn.address[0])
        
        if sni not in self.failed_domains:
            self.failed_domains.add(sni)
            logging.warning(f"[OCSP] TLS handshake failed for {sni}, disabling OCSP for this domain")
    
    def parse_and_validate_ocsp_response(self, ocsp_data: bytes, cert_chain: list[Certificate], conn_id) -> None:
        """Parse, validate signature, and display OCSP response details"""
        try:
            # Parse OCSP response using cryptography library
            ocsp_resp = ocsp.load_der_ocsp_response(ocsp_data)
            logging.info(f"[OCSP] Response Status: {ocsp_resp.response_status.name}")
            
            if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                # Validate the OCSP response signature
                signature_valid = validate_ocsp_signature(ocsp_resp, cert_chain)
                # Store serializable data
                if conn_id in self.ocsp_by_connection:
                    self.ocsp_by_connection[conn_id]["ocsp_cert_status"] = ocsp_resp.certificate_status.name
                    self.ocsp_by_connection[conn_id]["ocsp_signature_valid"] = signature_valid
                    self.ocsp_by_connection[conn_id]["ocsp_this_update"] = ocsp_resp.this_update_utc.isoformat()
                    if ocsp_resp.next_update_utc:
                        self.ocsp_by_connection[conn_id]["ocsp_next_update"] = ocsp_resp.next_update_utc.isoformat()
                    self.ocsp_by_connection[conn_id]["ocsp_serial_number"] = str(ocsp_resp.serial_number)
                
                if signature_valid:
                    logging.info(f"[OCSP] Signature validation: PASSED")
                else:
                    logging.error(f"[OCSP] Signature validation: FAILED")
                
                # Get certificate status
                logging.info(f"[OCSP] Certificate Status: {ocsp_resp.certificate_status.name}")

                # Check revocation reason if revoked
                if ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                    logging.info(f"[OCSP] Revocation Time: {ocsp_resp.revocation_time_utc}")
                    if ocsp_resp.revocation_reason:
                        logging.info(f"[OCSP] Revocation Reason: {ocsp_resp.revocation_reason.name}")
                    else:
                        logging.info(f"[OCSP] Revocation Reason: Unspecified")

                # Get timestamps
                logging.info(f"[OCSP] This Update: {ocsp_resp.this_update_utc}")
                if ocsp_resp.next_update_utc:
                    logging.info(f"[OCSP] Next Update: {ocsp_resp.next_update_utc}")
                logging.info(f"[OCSP] Produced at: {ocsp_resp.produced_at_utc} ")

                # Get serial number
                logging.info(f"[OCSP] Serial Number: {ocsp_resp.serial_number}")
                
                # Get responder information
                if ocsp_resp.responder_name:
                    logging.info(f"[OCSP] Responder Name: {ocsp_resp.responder_name.rfc4514_string()}")
                if ocsp_resp.responder_key_hash:
                    logging.info(f"[OCSP] Responder Key Hash: {ocsp_resp.responder_key_hash.hex()}")
                
                # Get hash algorithm
                #logging.info(f"[OCSP] Hash Algorithm: {ocsp_resp.hash_algorithm.name}")
                
                # Get signature algorithm
                logging.info(f"[OCSP] Signature Hash Algorithm: {ocsp_resp.signature_hash_algorithm.name}")

                # Check for extensions
                try:
                    extensions = ocsp_resp.single_extensions
                    if extensions:
                        logging.info(f"[OCSP] Found {len(extensions)} extension(s)")
                        for ext in extensions:
                            logging.info(f"[OCSP] Extension OID: {ext.oid.dotted_string} ({ext.oid._name if hasattr(ext.oid, '_name') else 'unknown'})")
                            logging.info(f"[OCSP] Extension Critical: {ext.critical}")

                            # Check for Signed Certificate Timestamp (SCT) extension
                            if ext.oid.dotted_string == "1.3.6.1.4.1.11129.2.4.5":           # OID for SCT List
                                logging.info(f"[OCSP] *** Signed Certificate Timestamp (SCT) Extension Found ***")
                                try:
                                    self.ocsp_by_connection[conn_id]["ocsp_contains_sct"] = True
                                    sct_list = ext.value
                                    logging.info(f"[OCSP] SCT List contains {len(sct_list)} SCT(s).")

                                    # Store sct_list for later parsing by CertGuard
                                    self.ocsp_sct_list[conn_id] = sct_list
                                    
                                    # Log SCT values
                                    for i, sct in enumerate(sct_list, 1):
                                        logging.info(f"[OCSP]   SCT #{i}:")
                                        logging.info(f"[OCSP]     Version: {sct.version.name}")
                                        logging.info(f"[OCSP]     Log ID: {sct.log_id.hex()}")
                                        logging.info(f"[OCSP]     Timestamp: {sct.timestamp}")
                                        logging.info(f"[OCSP]     Entry Type: {sct.entry_type.name}")
                                except Exception as e:
                                    logging.warning(f"[OCSP] Could not parse SCT extension: {e}")
                            else:
                                # Try to display the extension value
                                if isinstance(ext.value, UnrecognizedExtension):
                                    value_bytes = ext.value.value
                                else:
                                    value_bytes = ext.value
                                logging.info(f"[OCSP] Extension Value: value={repr(value_bytes)}")

                except AttributeError:
                    logging.debug("[OCSP] No extensions present in OCSP response")
                except Exception as e:
                    logging.warning(f"[OCSP] Error parsing OCSP extensions: {e}")
                
            logging.info(f"[OCSP] ==========================================")
            
        except Exception as e:
            logging.error(f"[OCSP] Error parsing OCSP response: {e}")
   
    def tls_established_server(self, data: tls.TlsData) -> None:
        """Called after TLS handshake is complete"""
        
        if not config.revocation_checks:
            return
        sni = data.conn.sni or str(data.conn.address[0])
        conn_id = id(data.conn)
        if conn_id in self.ocsp_by_connection:
            logging.info(f"[OCSP] TLS established with OCSP stapling for {sni}")
        else:
            logging.info(f"[OCSP] TLS established without OCSP stapling for {sni}")
