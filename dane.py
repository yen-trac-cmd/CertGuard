import dns
import dns.edns
import dns.exception
import dns.rcode    
import dns.message
import dns.query
import dns.rdatatype
#import dns.rdtypes
#from dns.rdtypes.IN import TLSA
import hashlib
import logging
from CertGuardConfig import Config
from cryptography import x509
from cryptography.hazmat.primitives import serialization #, hashes
from enum import IntEnum
from helper_functions import get_ede_description
from chain_builder import verify_signature
from mitmproxy import connection #tls, http, certs
from typing import Sequence, Optional, Tuple

CONFIG = Config()

class TLSA_Enum:
    """
    A container class for the enumerations defining a DANE TLSA record.
    """

    class Usage(IntEnum):
        """Translates the numeric usage field of a TLSA record."""
        WebPKI_CA_Constraint = 0
        WebPKI_EndEntity = 1
        DANE_TrustAnchor = 2
        DANE_EndEntity = 3

    class Selector(IntEnum):
        """Translates the numeric selector field of a TLSA record."""
        Full_Certificate = 0
        Subject_PublicKey_Info = 1

    class MatchingType(IntEnum):
        """Translates the numeric matching-type field of a TLSA record."""
        Exact_Match = 0
        SHA256 = 1
        SHA512 = 2

class DANETLSAValidator:
    """mitmproxy add-on for DANE TLSA validation."""
    
    def __init__(self):
        self.cache = {}
        self.stats = {"validated": 0, "dane_failed": 0, "no_tlsa": 0, "dns_failed": 0, "dnssec_failed": 0}

    def perform_dane_check(self, root_store, conn: connection.Server) -> None:
        """Performs DANE validation logic against certificate chain"""
        logging.warning(f"Flow Connection ID:       {conn.id}")
        conn.address
        hostname = conn.address[0]
        port = conn.address[1]
        
        # Get the server certificate
        if not conn or not hasattr(conn, 'certificate_list') or not conn.certificate_list:
            logging.debug(f"No certificate available for {hostname}")
            return

        chain = [cert.to_cryptography() for cert in conn.certificate_list]

        # Validate chain using DANE
        try:
            result, validation_error = self.validate_dane(root_store, hostname, port, chain)
        except Exception as e:
            logging.error(f"Error during DANE validation for {hostname}: {e}")
        
        self.dane_used = False
        self.dnssec_failure = False
        self.dane_failure = False
        self.violation = None

        #logging.debug(f'Return from validate_dane():  {result}')
        if result == "no_tlsa":
            self.dane_used = False
            self.stats["no_tlsa"] += 1
            logging.debug(f"DANE not in use for {hostname}.  {validation_error if validation_error else ""}")
        elif result == "dane_valid":
            self.dane_used = True
            self.stats["validated"] += 1
            logging.info(f"DANE validation successful for {hostname}")
        elif result == "dns_failed":
            self.dns_failure = True
            self.stats["dns_failed"] += 1
            error = f"⚠️ Encountered DNS failures while trying to lookup TLSA records.{f'<br>&emsp;&emsp;▶ DNS Error: ' + ", ".join(validation_error) if validation_error else ''}"
            logging.error(error)
            self.violation = error
        elif result == "dnssec_failed":
            self.dnssec_failure = True
            self.stats["dnssec_failed"] += 1
            logging.warning(f"DNSSEC validation failed for {hostname}")
            if CONFIG.require_dnssec:
                logging.error(f"DNSSEC validation failed for DANE TLSA record {hostname}.")
                self.violation = f"⛔ DNSSEC validation failed for DANE TLSA record. {f'<br>&emsp;&emsp;▶ DNS Error: ' + ", ".join(validation_error) if validation_error else ''}"
        elif result == "dane_failed":
            self.dane_failure = True
            self.stats["dane_failed"] += 1
            logging.error(f"DANE validation against published TLSA record for {hostname} failed.")
            self.violation = f"⛔ DANE validation against published TLSA record failed.{f'<br>&emsp;&emsp;▶ ' + ", ".join(validation_error) if validation_error else ''}"
        else:
            logging.error('Unexpected condition; failing closed')
            self.violation = f"⛔ Unepxected error encountered during DANE checks.{f'<br>&emsp;&emsp;▶ ' + ", ".join(validation_error) if validation_error else ''}"
    
    def validate_dane(self, root_store, hostname: str, port: int, chain: list[x509.Certificate]) -> str:
        """
        Validate certificate against TLSA records.
        Args:
            hostname:       FQDN from which to construct the TLSA DNS query
            port:           TCP port used for HTTPS connection
            cert_pem:       Server certificate in PEM-formatted bytes.

        Returns:
            "dane_valid":    DANE validation successful
            "dane_failed":   DANE validation failed
            "no_tlsa":       No TLSA record found
            "dns_failed":    Error encountered during DNS query
            "dnssec_failed": DNSSEC validation failed
        """
        #TODO: Move resolver logic for both dane.py and CertGuard.py checks into helper_functions.py.
        #TODO: Add support for DoH/DoQ to allow for safe use of public resolvers.
        logging.warning(f"-----------------------------------Entering validate_dane()---------------------------------------")
        

        # Check cache
        cache_key = (hostname, port)
        #logging.debug(f'Cache contains TLSA records for: {list(self.cache.keys())}')
        
        if cache_key in self.cache:
            tlsa_records = self.cache[cache_key]
            logging.debug(f'Found TLSA record(s) in session cache: {tlsa_records}')
        else:
            # Query for TLSA records
            tlsa_name = f"_{port}._tcp.{hostname}"
            logging.info(f'Querying for TLSA record {tlsa_name}')

            query = dns.message.make_query(tlsa_name, 'TLSA', want_dnssec=True)
            got_response = False

            while got_response == False:
                try:
                    current_resolver = CONFIG.resolvers[0]
                    logging.debug(f'Using resolver: {current_resolver}')
                    response = dns.query.udp_with_fallback(query, current_resolver, timeout=CONFIG.dns_timeout)
                    got_response = True
                except dns.exception.Timeout:
                    CONFIG.resolvers.rotate(1)
                    current_resolver = CONFIG.resolvers[0]
                    logging.error(f'DNS query for "{tlsa_name}" using resolver {CONFIG.resolvers[-1]} exceeded timeout of {CONFIG.dns_timeout} seconds.')
                    logging.error(f'  --> Trying again with resolver {current_resolver}.')
                except Exception as e:
                    CONFIG.resolvers.rotate(1)
                    current_resolver = CONFIG.resolvers[0]
                    logging.debug(f"Exception encountered for DNS query using resolver {CONFIG.resolvers[-1]}: {e}")
                    logging.error(f'  --> Trying again with resolver {current_resolver}.')

            if response[1]:
                logging.debug(f'DNS query had to fallback to TCP due to truncated response')
            response=response[0]
            logging.debug(f'Full resource record set:\n{response.to_text()}')

            # Check DNSSEC validation 
            if self.verify_dnssec(response):
                authenticated_data = True
                logging.info(f'DNSSEEC response validation successful (Authenticated Data bit set in response).')
            else:
                authenticated_data = False
                logging.warning(f'Response data could not be validated by DNSSEC.')

            ede_errors=[]
            if not response.rcode() == dns.rcode.NOERROR:
                logging.warning(f'Received {response.rcode().name} DNS response.')
                # Check for RFC8914 EDNS Extended DNS Error (EDE) information, if present, to explain failure(s)
                if response.options:
                    for opt in response.options:
                        # Handle only EDE options
                        if isinstance(opt, dns.edns.EDEOption):
                            # Note: opt objects also expose discrete .code and .text attributes (if returned by server).
                            logging.warning(f"Encountered {opt.to_text()}")
                            ede_errors.append(get_ede_description(opt.code))
                            #ede_errors.append(opt.to_text())

                if response.rcode() == dns.rcode.NXDOMAIN:
                    logging.warning(f'  --> No resource records exist for {tlsa_name}.')
                    return "no_tlsa", ede_errors
                elif response.rcode() == dns.rcode.SERVFAIL and ede_errors:
                    return "dnssec_failed", ede_errors
                elif response.rcode() == dns.rcode.FORMERR:
                    logging.error('  --> Query was malformed or otherwise uninterpretable by the DNS server.')
                    return "dns_failed", ede_errors
                elif response.rcode() == dns.rcode.NOTIMP:
                    logging.error('  --> DNS server does not support request type of DNS query.')
                    return "dns_failed", ede_errors
                elif response.rcode() == dns.rcode.REFUSED:
                    logging.error('  --> DNS server refused the DNS query.')
                    return "dns_failed", ede_errors
        
            # If reached here, can assume NOERROR response
            # Check for missing answers for TLSA query.
            tlsa_records = []
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.TLSA:
                    for rr in rrset:
                        tlsa_records.append(rr)
            if not tlsa_records:
                logging.warning(f'No TLSA records identified.')
                return "no_tlsa", ede_errors

            if not authenticated_data:
                return "dnssec_failed", ede_errors

            # Cache for future queries against same FQDN
            self.cache[cache_key] = tlsa_records  
            logging.debug(f'Added to TLSA record(s) to session cache under key {cache_key}.')

        # Fetch root
        no_root = True
        root = get_dane_root(chain, root_store)
        if root[0]:
            chain.append(root[0])
            no_root = False
        else:
            logging.error(f'Could not locate root certificate for presented chain with Subject of: {root[1]}')

        logging.warning(f'Length of chain (including root): {len(chain)}')
        #logging.warning(f'Chain (including root): {chain}')

        # Validate against each TLSA record
        x509_cert = chain[0]
        for tlsa in tlsa_records:
            dane_validated, dane_error = self.check_tlsa_record(tlsa, chain, x509_cert, no_root)
            if dane_validated:
                return "dane_valid", None
        
        # If landed here, no TLSA records matched
        return "dane_failed", dane_error

    def check_tlsa_record(self, tlsa: dns.rdata.Rdata, chain: list[x509.Certificate], cert: x509.Certificate, no_root: bool) -> bool:
        """
        Check if certificate matches TLSA record.
        
        TLSA record format:
        - usage (0-3): Certificate usage (0=PKIX-TrustAnchor, 1=PKIX-EndEntity, 2=DANE-TrustAnchor, 3=DANE-EndEntity)
        - selector (0-1): Which part to match (0=Full cert, 1=Subject Public Key Info)
        - matching_type (0-2): How to match (0=Exact data match, 1=SHA-256, 2=SHA-512)
        - cert_data: The certificate data to match (either full cert or SPKI)
        """
        #logging.warning(f"-----------------------------------Entering check_tlsa_record()------------------------------------------")
        usage = tlsa.usage
        selector = tlsa.selector
        matching_type = tlsa.mtype
        tlsa_cert_assoc_data = tlsa.cert

        # Get the data to match based on selector
        # TODO: This logic works if usage == 1 or usage == 3, but haven't encountered DANE-asserted self-signed certs or certs that chain to a private
        # PKI with usage types 0 or 2.

        if usage not in [0,1,2,3]:
            logging.error(f'Invalid DANE usage parameter: {usage}')
            return False, [f"Invalid DANE usage parameter: {usage}"]

        # Set type for later checking by, and potential bypass of Root, CAA, and CT functions in main module.
        self.dane_usage_type = usage

        if usage == 0 or usage == 2:
            if usage == 0 and no_root:  # MUST be able to chain up to root cert from local trust store for WebPKI Trust Anchor usage
                return False, [f"Could not verify cert chain against trusted WebPKI root cert."]
            
            if selector == 0:  # Full certificate
                # Extract all certs in chain except for leaf cert (which would only be appropriate for Usage type 1 or 3)
                data_list = [cert.public_bytes(encoding=serialization.Encoding.DER) for cert in chain[1:]]
            elif selector == 1:  # SubjectPublicKeyInfo
                data_list = [cert.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo) for cert in chain]
            else:
                logging.warning(f"Unknown DANE selector value: {selector}")
                return False, [f"Unknown DANE selector value: {selector}"]
            
            # Apply matching type
            if matching_type == 0:  # Exact match
                computed_list = data_list
            elif matching_type == 1:  # SHA-256
                computed_list = [hashlib.sha256(data).digest() for data in data_list]
            elif matching_type == 2:  # SHA-512
                computed_list = [hashlib.sha512(data).digest() for data in data_list]
            else:
                logging.warning(f"Unknown matching type: {matching_type}")
                return False, [f"Unknown matching type: {matching_type}"]

            logging.debug(f'Checking against TLSA record: {tlsa}')

            # Compare
            match = False
            for computed in computed_list:
                logging.debug(f'Computed value from chain cert to match against, based on TLSA selector and matching type: {computed.hex()}')
                if computed == tlsa_cert_assoc_data:
                    match = True
                    if usage == 2:
                        self.dane_ta_selector = TLSA_Enum.Selector(selector).name
                        self.dane_ta_matching_type = TLSA_Enum.MatchingType(matching_type).name
                        self.dane_ta_data = computed
                    break
        
        elif usage == 1 or usage == 3:
            if selector == 0:  # Full certificate
                data = cert.public_bytes(encoding=serialization.Encoding.DER)
            elif selector == 1:  # SubjectPublicKeyInfo
                data = cert.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            else:
                logging.warning(f"Unknown DANE selector value: {selector}")
                return False, [f"Unknown DANE selector value: {selector}"]
            
            # Apply matching type
            if matching_type == 0:  # Exact match
                computed = data
            elif matching_type == 1:  # SHA-256
                computed = hashlib.sha256(data).digest()
            elif matching_type == 2:  # SHA-512
                computed = hashlib.sha512(data).digest()
            else:
                logging.warning(f"Unknown matching type: {matching_type}")
                return False, [f"Unknown matching type: {matching_type}"]
        
            logging.debug(f'Computed value from certificate to match against, based on TLSA selector and matching type: {computed.hex()}')
            #logging.debug(f'Checking against TLSA record: {tlsa}')

            # Compare
            match = computed == tlsa_cert_assoc_data
            
        if match:
            logging.info(f"TLSA match:")
            logging.info(f"  - Certificate Usage:          {TLSA_Enum.Usage(usage).name} ({usage})") 
            logging.info(f"  - Selector:                   {TLSA_Enum.Selector(selector).name} ({selector})")
            logging.info(f"  - Matching Type:              {TLSA_Enum.MatchingType(matching_type).name} ({matching_type})")
            logging.info(f"  - Match Data (Computed):      {computed.hex()}")
            return match, None
        else:
            dane_error = ['Could not match TLSA record(s) against presented TLS certificate(s)']
            return match, dane_error
    
    def verify_dnssec(self, response: dns.message.QueryMessage) -> bool:
        """
        Confirm DNS response from recursive resolver has Authenticated Data (AD) flag set to indicate a validated DNSSEC response.
        """
        try:
            return response.flags & dns.flags.AD
        except Exception as e:
            logging.debug(f"DNSSEC check failed: {e}")
            return False

    def done(self) -> None:
        """Called when the add-on is unloaded."""
        print("DANE TLSA Validator statistics:")
        print(f"  Validated: {self.stats['validated']}")
        print(f"  Failed: {self.stats['dane_failed']}")
        print(f"  No TLSA: {self.stats['no_tlsa']}")
        print(f"  DNS Failed: {self.stats['dns_failed']}")
        print(f"  DNSSEC Failed: {self.stats['dnssec_failed']}") 

def get_dane_root(server_chain: Sequence[x509.Certificate], root_store: Sequence[x509.Certificate]) -> Tuple[Optional[x509.Certificate], Optional[str]]:
    """
    Given an x509.Certificate chain and trusted root store, attempt to identify the root CA certificate for the server's certificate chain.

    Args:
        chain (Sequence): Ordered x509 certificate chain presented by the server (leaf first, intermediates, and optionally a root cert)
        root_store (Sequence[x509.Certificate]): List of trusted root certificates to match against.
    Returns:
        Tuple[Optional[x509.Certificate], Optional[str]]: (root_cert, identifier)
            root_cert: matched root cert from root_store, or None if no match.
            identifier: CN (preferred) or full RFC 4514 subject string of the matched root cert, or None if no root identified.
    """
           
    # If using self-signed cert...
    if len(server_chain) == 1:
        self_signed = server_chain[0].issuer.rfc4514_string()
        logging.error(f'Self-signed certificate; Subject = {self_signed}')
        return (None, self_signed)

    logging.info(f'Length of presented chain:       {len(server_chain)}')
	
    # Verify last cert in chain against a trusted root anchors 
    last_cert = server_chain[-1]
    for root in root_store:
        if root.subject == last_cert.issuer:
            try:
                verify_signature(last_cert, root)
                logging.warning(f'Chain verified against Root CA: {root.subject.rfc4514_string()}')
                return (root, None)
            except Exception as e:
                logging.error(f"Root CA cert verification failed: {e}")
                continue
   
    logging.error(f"No stored trust anchor cert found")
    try:
        return (None, last_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)
    except:
        return (None, last_cert.issuer.rfc4514_string())