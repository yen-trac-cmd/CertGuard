import hashlib
import logging
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa, padding
from enum import Enum
from mitmproxy import certs
from requests_cache import CachedSession, timedelta
from typing import Sequence

def supported_ciphers_list() -> list[str]:
    """
    Read in cipher-mapping.txt retrieved from https://testssl.sh/3.2/etc/cipher-mapping.txt and return list of both OpenSSL and IANA ciphersuite names.
    """
    ciphers=[]
    with open('./resources/cipher-mapping.txt', 'r') as f:
        ciphers = [cipher_name for line in f for cipher_name in line.split()[2:4]]
    return ciphers

def load_public_suffix_list() -> list[str]:  
    """
    Loads Public Suffix List from https://publicsuffix.org/list/public_suffix_list.dat.
    """
    PSL_URL = 'https://publicsuffix.org/list/public_suffix_list.dat'
    public_suffix_list = []

    session = CachedSession('./resources/public_suffix_list.dat', expire_after=timedelta(days=5), stale_if_error=True, backend="filesystem", allowable_codes=[200])
    logging.info(f'Session cache contains {PSL_URL}? {session.cache.contains(url=PSL_URL)}')

    try:
        psl_response = session.get(PSL_URL)
        #psl_response = session.get('https://publicsuffix.org/list/public_suffix_list.datx')   # Bogus URL for fault testing
        psl_response.raise_for_status()
        if not psl_response.from_cache:
            logging.info(f"Fresh Public Suffix List successfully downloaded from {PSL_URL}, Status Code: {psl_response.status_code}")

    except Exception as e:
        logging.warning(f"Error encountered during fetch: {e}")
        logging.warning(f"...falling back to cached content. Check connectivity and site availability.")
        psl_response = session.get(PSL_URL, only_if_cached=True)
        if psl_response.status_code != 200:
            logging.critical(f'Cannot load Public Suffix List from network or local cache; failing closed.')
            logging.critical(f'Check network connectivity and site availability to {PSL_URL}')
            sys.exit()

    if psl_response.from_cache:
        logging.debug('Public Suffix List retreived from cache.')

    for line in psl_response.text.splitlines():
        if not line.strip().startswith('//') and line.strip():
            public_suffix_list.append(line.strip())
    
    return public_suffix_list

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

def calculate_spki_hash(cert: x509.Certificate, hash_type: str) -> str:
    """
    Calculates a hash against the provided certificate's Subject Public Key Information (SPKI) data.
    
    Args:
        cert:           An x509.Certificate object from the cryptography library.
        hash_type:      String value representing type of hash to return
        
    Returns:
        spki_hash:      The caclulated SPKI hash as a hexadecimal string.

    Notes:
        Calling this function with hash_type = "SHA1" returns one form a Subject Key Identifier (SKI) as defined at https://www.rfc-editor.org/rfc/rfc3280#section-4.2.1.2.
    """
    # Serialize the public key to the SubjectPublicKeyInfo DER format (SPKI)
    # Note: The 'SubjectPublicKeyInfo' is the specific structure required by RFC 5280
    public_key = cert.public_key()
    
    try:
        spki_der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception as e:
        logging.error(f'Unexpected exception serializing certificate public key: {e}')
    
    if hash_type == "SHA1":
        spki_hash = hashlib.sha1(spki_der).digest().hex()
    if hash_type == "SHA256":
        spki_hash = hashlib.sha256(spki_der).digest().hex()
    elif hash_type == "SHA512":
        spki_hash = hashlib.sha512(spki_der).digest().hex()
    
    return spki_hash

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

def verify_signature(subject: x509.Certificate, issuer: x509.Certificate) -> None:
    """
    Cryptographically verify that `issuer` signed `subject`.
        Handles RSA (PKCS#1 v1.5 and basic PSS), ECDSA, Ed25519/Ed448, and DSA.
    
    Args:
        subject:    x509.Certificate object signed by issuer
        issuer:     x509.Certificate object from which signature on subject will be verified
    
    Returns:
        None:       An exception is raised if digital signature verification fails, otherwise verification was successful.
    """
    # For debugging purposes only
    #from cryptography.hazmat.primitives import serialization
    #logging.error(f'Subject PEM bytes: {(subject.public_bytes(serialization.Encoding.PEM)).decode("utf-8")}')
    #logging.info('-----------------------------------')
    #logging.error(f'Issuer PEM bytes: {(issuer.public_bytes(serialization.Encoding.PEM)).decode("utf-8")}')
        
    pub = issuer.public_key()
    oid = subject.signature_algorithm_oid
    h = subject.signature_hash_algorithm  # a HashAlgorithm instance, or None for EdDSA

    if isinstance(pub, rsa.RSAPublicKey):
        # Handle RSA-PSS vs RSA-PKCS1v1.5
        if oid == x509.SignatureAlgorithmOID.RSASSA_PSS:
            # Best-effort PSS parameters: MGF1 with same hash; salt len = hash length.
            # (Parsing explicit PSS params is possible but longer; this covers common cases.)
            pub.verify(
                signature=subject.signature,
                data=subject.tbs_certificate_bytes,
                padding=padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size),
                algorithm=h,
            )
        else:
            #try:
            pub.verify(signature=subject.signature, data=subject.tbs_certificate_bytes, padding=padding.PKCS1v15(), algorithm=h)
            #except Exception as e:
            #    logging.critical(f'Error: {e}')

    elif isinstance(pub, ec.EllipticCurvePublicKey):
        # ECDSA takes a signature algorithm wrapper with the hash
        pub.verify(signature=subject.signature, data=subject.tbs_certificate_bytes, signature_algorithm=ec.ECDSA(h))

    elif isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(subject.signature, subject.tbs_certificate_bytes)

    elif isinstance(pub, ed448.Ed448PublicKey):
        pub.verify(subject.signature, subject.tbs_certificate_bytes)

    elif isinstance(pub, dsa.DSAPublicKey):
        pub.verify(signature=subject.signature, data=subject.tbs_certificate_bytes, algorithm=h,)

    else:
        raise TypeError(f"Unsupported public key type: {type(pub)}")

def clean_error(html_string):
    """Strips HTML tags using lxml and removes unicode characters to produce text-only error."""
    from lxml.html import fromstring
    import re

    cz_to_replace = r"🛈|ℹ️|⛔|⚠️|&nbsp;|&emsp;|▶"
    
    error_text = re.sub(cz_to_replace, '', html_string).strip()
    tree = fromstring(error_text)
    clean_error_text = tree.text_content()
    
    return clean_error_text