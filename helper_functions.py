import hashlib
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from enum import Enum
from mitmproxy import certs
from typing import Sequence

def supported_ciphers_list() -> list[str]:
    """
    Read in cipher-mapping.txt retrieved from https://testssl.sh/3.2/etc/cipher-mapping.txt and return list of both OpenSSL and IANA ciphersuite names.
    """
    ciphers=[]
    with open('./resources/cipher-mapping.txt', 'r') as f:
        ciphers = [cipher_name for line in f for cipher_name in line.split()[2:4]]
    return ciphers

def get_cert_domains(x509_cert: certs.Cert) -> list[str]:
    """
    Extract CN and DNS SubAltNames from a mitmproxy.certs.Cert object.

    Args:
        x509_cert (mitmproxy.certs.Cert): A mitmproxy.certs.Cert object containing the certificate to extract domains from.

    Returns:
        list[str]: A de-duplicated list of FQDN strings, in lower-case, found in the supplied certificate.
    """
    domains = set()

    # Subject CN
    for attr in x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
        domains.add(attr.value.lower())

    # SANs
    try:
        san_ext = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value.get_values_for_type(x509.DNSName):
            domains.add(name.lower())
    except x509.ExtensionNotFound:
        pass

    return list(domains)

def calculate_ski(certificate_obj: x509.Certificate) -> str:
    """
    Calculates the SHA-1 Subject Key Identifier (SKI) from a certificate's public key.
    
    Args:
        certificate_obj: An x509.Certificate object from the cryptography library.
        
    Returns:
        The SKI as a hexadecimal string.
    """
    public_key = certificate_obj.public_key()
    # Serialize the public key to the SubjectPublicKeyInfo DER format (SPKI)
    # Note: The 'SubjectPublicKeyInfo' is the specific structure required by RFC 5280
    spki_der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    # Calculate the hex-encoded SHA-1 hash of the SPKI DER bytes 
    ski_hex = hashlib.sha1(spki_der).digest().hex()
        
    return ski_hex

def get_ede_description(code: int) -> str:
    """Returns a descriptive string for Extended DNS Error (EDE) codes defined in RFC 8914 and IANA assignments.

    Args:
        code (int): The Extended DNS Error (EDE) code to get the description for.

    Returns:
        str: The descriptive string for the given EDE code.
    """
    EDE_CODES_MAP = {
        0: "Other/unspecified error",
        1: "Unsupported DNSKEY Algorithm",
        2: "Unsupported DS Digest Type",
        3: "Stale DNSSEC Answer",
        4: "Forged DNSSEC Answer",
        5: "DNSSEC Indeterminate Error",
        6: "Invalid signature ('DNSSEC Bogus')",
        7: "DNSSEC Signature Expired",
        8: "DNSSEC Signature Not Yet Valid",
        9: "DNSSEC DNSKEY Missing",
        10: "DNSSEC RRSIGs Missing",
        11: "No Zone Key Bit Set",
        12: "NSEC Missing",
        13: "Resolver returned SERVFAIL RCODE from cache",
        14: "DNS Server Not Ready",
        15: "Domain blocklisted by DNS server operator",
        16: "Domain Censored",
        17: "Domain Filtered (as requested by client)",
        18: "Request Prohibited (client unauthorized)",
        19: "Stale NXDOMAIN Answer",
        20: "Authoritative Nameserver(s) unreachable",
        21: "Requested operation or query not supported",
        22: "No Reachable Authority",
        23: "Network Error",
        24: "Invalid Data",
    }
    return EDE_CODES_MAP.get(code, "Unknown EDE Code")

def deduplicate_chain(cert_chain: Sequence[x509.Certificate]) -> Sequence[x509.Certificate]:
    """ Removes duplicate certs from provided certificate chain """
    seen = set()
    unique_chain = []
    for cert in cert_chain:
        fingerprint = cert.fingerprint(hashes.SHA256())
        if fingerprint not in seen:
            seen.add(fingerprint)
            unique_chain.append(cert)
        else:
            logging.warning(f"Duplicate certificate detected: {cert.subject.rfc4514_string()}")
    return unique_chain