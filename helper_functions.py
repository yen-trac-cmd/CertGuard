import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from mitmproxy import certs

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
        x509_cert (mitmproxy.certs.Cert)

    Returns:
        list: A de-duplicated list of FQDN strings, in lower-case, found in the supplied certificate.
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

def calculate_ski(certificate_obj):
    """
    Calculates the Subject Key Identifier (SKI) from a certificate's public key.
    
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