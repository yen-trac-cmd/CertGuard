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
from typing import Optional
import dns.resolver
import dns.dnssec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from mitmproxy import ctx, http, certs, tls

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

       ###################################################
        # The upstream connection is stored in data.context.server
        server_conn = data.context.server
        chain = server_conn.certificate_list     # List of mitmproxy.certs.Cert objects (leaf first)
        if not chain:
            ctx.log.warn("Upstream sent no certs.")
            return

        cert = chain[0].to_cryptography()
        ctx.log.info(f"Upstream Subject: {cert.subject.rfc4514_string()}")

        ######################################################

        hostname = data.context.server.address[0]
        ctx.log.info(f'Identified hostname as: {hostname}')
        port = data.context.server.address[1]
        
        # Get the server certificate
        conn = data.context.server
        if not conn or not hasattr(conn, 'certificate_list') or not conn.certificate_list:
            ctx.log.debug(f"No certificate available for {hostname}")
            return

        cert_der = conn.certificate_list[0].to_pem()
        # cert_der is now PEM-formatted ASCII 'bytes' boject

        # Validate using DANE
        try:
            result = self.validate_dane(hostname, port, cert_der)
            
            if result == "valid":
                self.stats["validated"] += 1
                ctx.log.info(f"✓ DANE validation successful for {hostname}")
            elif result == "no_tlsa":
                self.stats["no_tlsa"] += 1
                ctx.log.debug(f"No TLSA record found for {hostname}")
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
    
    def validate_dane(self, hostname: str, port: int, cert_der: bytes) -> str:
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
                
            except dns.resolver.NXDOMAIN:
                ctx.log.debug(f"No TLSA record for {tlsa_name}")
                return "no_tlsa"
            except dns.resolver.NoAnswer:
                return "no_tlsa"
            except Exception as e:
                ctx.log.debug(f"DNS query failed for {tlsa_name}: {e}")
                return "no_tlsa"
        
        if not tlsa_records:
            return "no_tlsa"
        
        # Parse certificate
        cert = x509.load_pem_x509_certificate(cert_der)
        
        # Validate against each TLSA record
        for tlsa in tlsa_records:
            if self.check_tlsa_record(tlsa, cert, cert_der):
                return "valid"
        
        return "failed"
    
    def check_tlsa_record(self, tlsa, cert: x509.Certificate, cert_der: bytes) -> bool:
        """
        Check if certificate matches TLSA record.
        
        TLSA record format:
        - usage (0-3): Certificate usage (0=PKIX-TrustAnchor, 1=PKIX-EndEntity, 2=DANE-TrustAnchor, 3=DANE-EndEntity)
        - selector (0-1): Which part to match (0=Full cert, 1=Subject Public Key Info)
        - matching_type (0-2): How to match (0=Exact data match, 1=SHA-256, 2=SHA-512)
        - cert_data: The certificate data to match (either full cert or SPKI)
        """
        ctx.log.warn(f"-----------------------------------Entering check_tlsa_records()---------------------------------------------")
        usage = tlsa.usage
        selector = tlsa.selector
        matching_type = tlsa.mtype
        cert_assoc_data = tlsa.cert
        
        # Get the data to match based on selector
        if selector == 0:  # Full certificate
            data = cert_der
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
        match = computed == cert_assoc_data
        
        if match:
            ctx.log.info(f"TLSA match: usage={usage}, selector={selector}, matching_type={matching_type}")
        
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