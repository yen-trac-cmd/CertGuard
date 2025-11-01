"""
mitmproxy add-on implementing RFC 6698 DANE protocol for TLSA record validation.

This add-on validates HTTPS connections using TLSA records (if present) from DNSSEC-signed zones.
It checks certificate associations according to the DANE specification.

Usage:
    mitmproxy -s dane_tlsa_addon.py

Requirements:
    pip install mitmproxy dnspython cryptography
"""

import dns
import dns.edns
import dns.exception
import dns.rcode    
import dns.resolver
import dns.message
import dns.query

#from dns.exception import DNSException
#from dns.resolver import Answer
#import dns.rcode
#import dns.edns
#import dns.dnssec
#from dns.rcode import SERVFAIL
#from dns.resolver import dns
#from dns import rdtypes

import hashlib
#from typing import Optional
import logging
from CertGuardConfig import Config
from cryptography import x509
from cryptography.hazmat.primitives import serialization #, hashes
from error_screen import error_screen
from mitmproxy import tls  #ctx, http, certs
from enum import IntEnum

CONFIG = Config()

class TLSA:
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
        self.resolver = dns.resolver.Resolver()
        self.resolver.use_edns(0, dns.flags.DO, 4096)  # Enable DNSSEC

        #TODO: Move resolver config to CertGuardConfig.py for both dane.py and CertGuard.py checks
        self.resolver.nameservers = ['8.8.8.8']

        self.cache = {}
        self.stats = {"validated": 0, "failed": 0, "no_tlsa": 0, "dns_failed": 0, "dnssec_failed": 0}
    
    '''
    def load(self, loader):
        """Called when the add-on is loaded."""
        loader.add_option(
            name="dane_enforce",
            typespec=bool,
            default=False,
            help="Enforce DANE validation (block connections on failure)"
        )
        loader.add_option(
            name="dane_require_dnssec",
            typespec=bool,
            default=False,
            help="Require DNSSEC validation for TLSA records"
        )
        logging.info("DANE TLSA Validator loaded")
    '''

    def tls_established_client(self, data: tls.TlsData):
        """Called when TLS is established with the upstream server."""
        
        logging.warning(f"===================================BEGIN DANE Check===================================================================")
        if not data.context.server.address:
            return

        hostname = data.context.server.address[0]
        logging.info(f'Identified hostname from mitmproxy data.context.server: {hostname}')
        port = data.context.server.address[1]
        
        # Get the server certificate
        conn = data.context.server
        if not conn or not hasattr(conn, 'certificate_list') or not conn.certificate_list:
            logging.debug(f"No certificate available for {hostname}")
            return
        cert = conn.certificate_list[0]
               
        cert_pem = cert.to_pem()    # Convert cert into a 'bytes' object of the PEM-formatted / ASCII representation of the cert

        # Validate using DANE
        try:
            result = self.validate_dane(hostname, port, cert_pem)
            
            self.dane_used = False
            self.dnssec_failure = False
            self.dane_failure = False

            if result == "valid":
                self.dane_used = True
                self.stats["validated"] += 1
                logging.info(f"DANE validation successful for {hostname}")
            elif result == "no_tlsa":
                self.dane_used = False
                self.stats["no_tlsa"] += 1
                logging.debug(f"DANE not in use for {hostname}")
            elif result == "dns_failed":
                self.stats["dns_failed"] += 1
            elif result == "dnssec_failed":
                self.stats["dnssec_failed"] += 1
                logging.warning(f"DNSSEC validation failed for {hostname}")
                if CONFIG.require_dnssec:
                    logging.error(f"DNSSEC validation failed for DANE TLSA record {hostname}.")
                    self.violation = f'⛔ DNSSEC validation failed for DANE TLSA record.'
                    self.dnssec_failure = True
            else:
                self.stats["failed"] += 1
                logging.error(f"DANE validation FAILED for {hostname}")
                if CONFIG.enforce_dane:
                    logging.error("DANE validation against published TLSA record failed; closing connection per configuration directive.")
                    self.violation = f"⛔ DANE validation against published TLSA record failed."
                    self.dane_failure = True
            
        except Exception as e:
            logging.error(f"Error during DANE validation for {hostname}: {e}")
    
    def validate_dane(self, hostname: str, port: int, cert_pem: bytes) -> str:
        """
        Validate certificate against TLSA records.
        Args:
            hostname:       FQDN from which to construct the TLSA DNS query
            port:           TCP port used for HTTPS connection
            cert_pem:       Server certificate in PEM-formatted bytes.

        Returns:
            "valid":         DANE validation successful
            "failed":        DANE validation failed
            "no_tlsa":       No TLSA record found
            "dns_failed":    Error encountered during DNS query
            "dnssec_failed": DNSSEC validation failed
        """
        logging.warning(f"-----------------------------------Entering validate_dane()---------------------------------------------")
        # Construct TLSA query name: _port._tcp.hostname
        tlsa_name = f"_{port}._tcp.{hostname}"
        logging.info(f'Querying for TLSA record {tlsa_name}')

        # Check cache
        cache_key = (hostname, port)
        if cache_key in self.cache:
            tlsa_records = self.cache[cache_key]
        else:
            # Query for TLSA records
            query = dns.message.make_query(tlsa_name, 'TLSA', want_dnssec=True)
            got_response = False

            while got_response == False:
                try:
                    #TODO: Move resolver logic for both dane.py and CertGuard.py checks into helper_functions.py.
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
                logging.warning(f'DNS query had to fallback to TCP due to truncated response')
            response=response[0]
            logging.debug(f'Full resource record set:\n{response.to_text()}')

            # Check DNSSEC validation 
            if self.verify_dnssec(response):
                validation_failed = False
                logging.info(f'DNSSEEC response validation successful (Authenticated Data bit set in response).')
            else:
                validation_failed = True
                logging.warning(f'Response data could not be validated by DNSSEC.')

            # Check for RFC8914 EDNS Extended DNS Error (EDE) information, if present, to explain failure(s)
            if response.options:
                for opt in response.options:
                    ede_errors=[]
                    # Handle only EDE options
                    if isinstance(opt, dns.edns.EDEOption):
                        # Note: opt objects also expose discrete .code and .text attributes if needed for future logic.
                        logging.warning(f"Encountered {opt}")
                        ede_errors.append(opt)
                        
                        '''
                        # Extract EDE information as defined in https://www.rfc-editor.org/rfc/rfc8914.html.
                        if opt.code == 0:
                            logging.warning(f"Other/unspecified error: {opt.text}")
                            return "dns_failed"
                        elif opt.code == 1:
                            logging.warning("Unsupported DNSKEY Algorithm.")
                            return "dnssec_failed"
                        elif opt.code == 2:
                            logging.warning("Unsupported DS Digest Type.")
                            return "dnssec_failed"
                        elif opt.code == 3:
                            logging.warning("Stale DNSSEC answer.")
                            return "dnssec_failed"
                        elif opt.code == 4:
                            logging.warning("Forged DNSSEC answer.")
                            return "dnssec_failed"
                        elif opt.code == 5:
                            logging.warning("DNSSEC Indeterminate error.")
                            return "dnssec_failed"
                        elif opt.code == 6:
                            logging.warning("Invalid signature ('DNSSEC Bogus').")
                            return "dnssec_failed"
                        elif opt.code == 7:
                            logging.warning("DNSSEC signature expired.")
                            return "dnssec_failed"
                        elif opt.code == 8:
                            logging.warning("DNSSEC signature not yet valid.")
                            return "dnssec_failed"
                        elif opt.code == 9:
                            logging.warning("DNSSEC DNSKEY missing.")
                            return "dnssec_failed"
                        elif opt.code == 10:
                            logging.warning("DNSSEC RRSIGs missing.")
                            return "dnssec_failed"
                        elif opt.code == 11:
                            logging.warning("No Zone Key Bit Set.")
                            return "dnssec_failed"
                        elif opt.code == 12:
                            logging.warning("NSEC Missing.")
                            return "dnssec_failed"
                        elif opt.code == 13:
                            logging.warning("Resolver returned SERVFAIL RCODE from cache.")
                            return "dns_failed"
                        elif opt.code == 14:
                            logging.warning("Server Not Ready.")
                            return "dns_failed"
                        elif opt.code == 15:
                            logging.warning("Domain blocklisted by DNS server operator.")
                            return "dns_failed"
                        elif opt.code == 16:
                            logging.warning("Domain Censored.")
                            return "dns_failed"
                        elif opt.code == 17:
                            logging.warning("Domain Filtered as requested by client.")
                            return "dns_failed"
                        elif opt.code == 18:
                            logging.warning("Request Prohibited; client unauthorized.")
                            return "dns_failed"
                        elif opt.code == 19:
                            logging.warning("Stale NXDOMAIN answer.")
                            return "dns_failed"
                        elif opt.code == 20:
                            logging.warning("Not Authoritative.")
                            return "dns_failed"
                        elif opt.code == 21:
                            logging.warning("Requested operation or query not supported.")
                            return "dns_failed"
                        elif opt.code == 22:
                            logging.warning("No Reachable Authoritative Nameserver.")
                            return "dns_failed"
                        elif opt.code == 23:
                            logging.warning("Network Error.")
                            return "dns_failed"
                        elif opt.code == 24:
                            logging.warning("Invalid Data.")
                            return "dns_failed"
                        '''

            if response.rcode() == dns.rcode.FORMERR:
                logging.error('Received Format error; query was malformed or otherwise uninterpretable by the DNS server.')
                return "dns_failed"

            if response.rcode() == dns.rcode.SERVFAIL:
                logging.error('Received SERVFAIL response.')
                return "dns_failed"

            if response.rcode() == dns.rcode.NXDOMAIN:
                logging.error('Received NXDOMAIN response.')
                return "no_tlsa"

            if response.rcode() == dns.rcode.NOTIMP:
                logging.error('DNS server does not support request type of DNS query.')
                return "dns_failed"

            if response.rcode() == dns.rcode.REFUSED:
                logging.error('DNS server refused the DNS query.')
                return "dns_failed"

            # Assume NOERROR response
            tlsa_records = [rr for rr in response]
            self.cache[cache_key] = tlsa_records

        if not tlsa_records:
            return "no_tlsa"
        
        # Parse certificate
        x509_cert = x509.load_pem_x509_certificate(cert_pem)
        
        # Validate against each TLSA record
        for tlsa in tlsa_records:
            if self.check_tlsa_record(tlsa, x509_cert, cert_pem):
                return "valid"
        
        return "failed"
    
    def check_tlsa_record(self, tlsa, cert: x509.Certificate, cert_pem: bytes) -> bool:
        """
        Check if certificate matches TLSA record.
        
        TLSA record format:
        - usage (0-3): Certificate usage (0=PKIX-TrustAnchor, 1=PKIX-EndEntity, 2=DANE-TrustAnchor, 3=DANE-EndEntity)
        - selector (0-1): Which part to match (0=Full cert, 1=Subject Public Key Info)
        - matching_type (0-2): How to match (0=Exact data match, 1=SHA-256, 2=SHA-512)
        - cert_data: The certificate data to match (either full cert or SPKI)
        """
        usage = tlsa.usage
        selector = tlsa.selector
        matching_type = tlsa.mtype
        tlsa_cert_assoc_data = tlsa.cert
        
        logging.debug(f'Checking against TLSA record: {tlsa}')

        # Get the data to match based on selector
        # TODO: This logic Works if usage == 1 or usage == 3, but need more code to account for usage types 0 and 2.
        if selector == 0:  # Full certificate
            data = cert_pem
        elif selector == 1:  # SubjectPublicKeyInfo
            data = cert.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            logging.warning(f"Unknown selector value: {selector}")
            return False
        
        # Apply matching type
        if matching_type == 0:  # Exact match
            computed = data
        elif matching_type == 1:  # SHA-256
            computed = hashlib.sha256(data).digest()
        elif matching_type == 2:  # SHA-512
            computed = hashlib.sha512(data).digest()
        else:
            logging.warning(f"Unknown matching type: {matching_type}")
            return False
        
        # Compare
        match = computed == tlsa_cert_assoc_data
        
        if match:
            logging.info(f"TLSA match: \n"
                f"  - Certificate Usage:   {TLSA.Usage(usage).name} ({usage})\n" 
                f"  - Selector:            {TLSA.Selector(selector).name} ({selector})\n"
                f"  - Matching Type:       {TLSA.MatchingType(matching_type).name} {matching_type} ()\n"
                f"  - Matched Data:        {computed.hex()}")
        
        return match
    
    def verify_dnssec(self, response: dns.message.QueryMessage) -> bool:
        """
        Confirm DNS response from recursive resolver has Authenticated Data (AD) flag set to indicate a validated DNSSEC response.
        """
        try:
            return response.flags & dns.flags.AD
        except Exception as e:
            logging.debug(f"DNSSEC check failed: {e}")
            return False
    
    def done(self):
        """Called when the add-on is unloaded."""
        print("DANE TLSA Validator statistics:")
        print(f"  Validated: {self.stats['validated']}")
        print(f"  Failed: {self.stats['failed']}")
        print(f"  No TLSA: {self.stats['no_tlsa']}")
        print(f"  DNSSEC Failed: {self.stats['dnssec_failed']}")