from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dns.resolver import dns
from mitmproxy import certs

def supported_ciphers_list() -> list[str]:
    """
    Read in cipher-mapping.txt retrieved from https://testssl.sh/3.2/etc/cipher-mapping.txt and return list of both OpenSSL and IANA ciphersuite names.
    """
    ciphers=[]
    with open('./resources/cipher-mapping.txt', 'r') as f:
        ciphers = [cipher_name for line in f for cipher_name in line.split()[2:4]]
    return ciphers

def cert_to_x509(cert: certs.Cert) -> x509.Certificate:
    """ 
    Convert a mitmproxy.certs.Cert or OpenSSL.crypto.X509 object into a cryptography.x509.Certificate.

    """
    pem_bytes = cert.to_pem()  # returns standard PEM
    return x509.load_pem_x509_certificate(pem_bytes, default_backend())

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