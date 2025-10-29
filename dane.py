"""
mitmproxy add-on implementing RFC 6698 DANE protocol for TLSA record validation.

This add-on validates HTTPS connections using TLSA records (if present) from DNSSEC-signed zones.
It checks certificate associations according to the DANE specification.

Usage:
    mitmproxy -s dane_tlsa_addon.py

Requirements:
    pip install mitmproxy dnspython cryptography
"""

import hashlib
#from typing import Optional
import dns.resolver
#import dns.dnssec
from dns import rdtypes
from cryptography import x509
from cryptography.hazmat.primitives import serialization #, hashes
from mitmproxy import ctx, tls  #, http, certs
from enum import IntEnum

class TLSA:
    """
    A container class for the enumerations defining a DANE TLSA record.
    """

    class Usage(IntEnum):
        """Translates the numeric usage field of a TLSA record."""
        PKIX_TA = 0
        PKIX_EE = 1
        DANE_TA = 2
        DANE_EE = 3

    class Selector(IntEnum):
        """Translates the numeric selector field of a TLSA record."""
        CERT = 0
        SPKI = 1

    class MatchingType(IntEnum):
        """Translates the numeric matching-type field of a TLSA record."""
        FULL = 0
        SHA256 = 1
        SHA512 = 2


class DANETLSAValidator:
    """mitmproxy add-on for DANE TLSA validation."""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.use_edns(0, dns.flags.DO, 4096)  # Enable DNSSEC
        self.cache = {}
        self.stats = {"validated": 0, "failed": 0, "no_tlsa": 0, "dnssec_failed": 0}
    
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
        ctx.log.info("DANE TLSA Validator loaded")
    
    def tls_established_client(self, data: tls.TlsData):
        """Called when TLS is established with the upstream server."""
        
        ctx.log.warn(f"===================================BEGIN DANE Check===================================================================")
        if not data.context.server.address:
            return

        hostname = data.context.server.address[0]
        ctx.log.info(f'Identified hostname from mitmproxy data.context.server: {hostname}')
        port = data.context.server.address[1]
        
        # Get the server certificate
        conn = data.context.server
        if not conn or not hasattr(conn, 'certificate_list') or not conn.certificate_list:
            ctx.log.debug(f"No certificate available for {hostname}")
            return

        cert = conn.certificate_list[0]
        #x509_cert = cert.to_cryptography()
        #ctx.log.info(f"Upstream Subject from cert: {x509_cert.subject.rfc4514_string()}")
                
        cert_pem = cert.to_pem()    # Convert cert into a 'bytes' object of the PEM-formatted / ASCII representation of the cert

        # Validate using DANE
        try:
            result = self.validate_dane(hostname, port, cert_pem)
            
            if result == "valid":
                self.stats["validated"] += 1
                ctx.log.info(f"DANE validation successful for {hostname}")
            elif result == "no_tlsa":
                self.stats["no_tlsa"] += 1
                ctx.log.debug(f"DANE not in use for {hostname}")
            elif result == "dnssec_failed":
                self.stats["dnssec_failed"] += 1
                ctx.log.warn(f"DNSSEC validation failed for {hostname}")
                if ctx.options.dane_enforce:
                    data.conn.close()
            else:  # failed
                self.stats["failed"] += 1
                ctx.log.error(f"DANE validation FAILED for {hostname}")
                if ctx.options.dane_enforce:
                    data.conn.close()
            
        except Exception as e:
            ctx.log.error(f"Error during DANE validation for {hostname}: {e}")
    
    def validate_dane(self, hostname: str, port: int, cert_pem: bytes) -> str:
        """
        Validate certificate against TLSA records.
        
        Returns:
            "valid": DANE validation successful
            "failed": DANE validation failed
            "no_tlsa": No TLSA record found
            "dnssec_failed": DNSSEC validation failed
        """
        ctx.log.warn(f"-----------------------------------Entering validate_dane()---------------------------------------------")
        # Construct TLSA query name: _port._tcp.hostname
        tlsa_name = f"_{port}._tcp.{hostname}"
        ctx.log.info(f'Querying for TLSA record {tlsa_name}')

        # Check cache
        cache_key = (hostname, port)
        if cache_key in self.cache:
            tlsa_records = self.cache[cache_key]
        else:
            # Query for TLSA records
            try:
                answer = self.resolver.resolve(tlsa_name, 'TLSA')

                # Check DNSSEC validation if required
                if ctx.options.dane_require_dnssec:
                    if not self.verify_dnssec(answer):
                        return "dnssec_failed"
                
                tlsa_records = [rr for rr in answer]
                self.cache[cache_key] = tlsa_records

                #ctx.log.warn(f'tlsa_records list: {tlsa_records}')

            except dns.resolver.NXDOMAIN:
                ctx.log.debug(f"TLSA resource record not found for {tlsa_name}")
                return "no_tlsa"
            except dns.resolver.NoAnswer:
                return "no_tlsa"
            except Exception as e:
                ctx.log.debug(f"DNS query failed for {tlsa_name}: {e}")
                return "no_tlsa"
        
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
        
        ctx.log.debug(f'Checking against TLSA record: {tlsa}')

        # Get the data to match based on selector
        if selector == 0:  # Full certificate
            data = cert_pem
        elif selector == 1:  # SubjectPublicKeyInfo
            data = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            ctx.log.warn(f"Unknown selector value: {selector}")
            return False
        
        # Apply matching type
        if matching_type == 0:  # Exact match
            computed = data
        elif matching_type == 1:  # SHA-256
            computed = hashlib.sha256(data).digest()
        elif matching_type == 2:  # SHA-512
            computed = hashlib.sha512(data).digest()
        else:
            ctx.log.warn(f"Unknown matching type: {matching_type}")
            return False
        
        # Compare
        match = computed == tlsa_cert_assoc_data
        
        if match:
            ctx.log.info(f"TLSA match: \n"
                f"  - Certificate Usage:   {usage} ({TLSA.Usage(usage).name})\n" 
                f"  - Selector:            {selector} ({TLSA.Selector(selector).name})\n"
                f"  - Matching Type:       {matching_type} ({TLSA.MatchingType(matching_type).name})\n"
                f"  - Matched Data:        {computed.hex()}")
        
        return match
    
    def verify_dnssec(self, answer) -> bool:
        """
        Verify DNSSEC validation of the answer.
        Note: This is a simplified check. Full DNSSEC validation is complex.
        """
        try:
            # Check if the recursive resolver validated DNSSEC (e.g. answer has the Authenticated Data (AD) flag set).
            return answer.response.flags & dns.flags.AD != 0
        except Exception as e:
            ctx.log.debug(f"DNSSEC check failed: {e}")
            return False
    
    def done(self):
        """Called when the add-on is unloaded."""
        ctx.log.info("DANE TLSA Validator statistics:")
        ctx.log.info(f"  Validated: {self.stats['validated']}")
        ctx.log.info(f"  Failed: {self.stats['failed']}")
        ctx.log.info(f"  No TLSA: {self.stats['no_tlsa']}")
        ctx.log.info(f"  DNSSEC Failed: {self.stats['dnssec_failed']}")