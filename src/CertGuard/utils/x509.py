import hashlib
import logging
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

def get_cert_domains(x509_cert: x509.Certificate) -> list[str]:
    """
    Extract CN and DNS SubAltNames from a cryptography.x509.Certificate object.

    Args:
        x509_cert: An x.509 Certificate object from which to extract FQDNs.

    Returns:
        list[str]: A de-duplicated list of lower-case FQDN strings found in the supplied certificate.
    """
    domains = set()

    # Extract Subject CN
    for attr in x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
        domains.add(attr.value.lower())

    # Extract SANs
    try:
        san_ext = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value.get_values_for_type(x509.DNSName):
            domains.add(name.lower())
    except x509.ExtensionNotFound:
        pass

    return list(domains)

def calculate_spki_hash(cert: x509.Certificate, hash_type: str, hex: bool = False) -> str:
    """
    Calculates a hash against the provided certificate's Subject Public Key Information (SPKI) data.
    
    Args:
        cert:           A cryptography.x509.Certificate object.
        hash_type:      String value representing type of hash to return.
        hex:            Boolean to indicate if the returned value should be in hexadicmal form.
        
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
        spki_hash = hashlib.sha1(spki_der).digest()
    if hash_type == "SHA256":
        spki_hash = hashlib.sha256(spki_der).digest()
    elif hash_type == "SHA512":
        spki_hash = hashlib.sha512(spki_der).digest()
    
    if hex == True:
        return spki_hash.hex()

    return spki_hash

def get_extension_value(cert, oid, attr=None):
    """Safely extract extension value, optionally accessing a nested attribute."""
    try:
        ext = cert.extensions.get_extension_for_oid(oid).value
        return getattr(ext, attr) if attr else ext
    except Exception:
        return None

def get_spkid(cert):
    """Extract Subject Public Key Identifier."""
    try:
        ski_extension = get_extension_value(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER, 'digest')
    except x509.ExtensionNotFound:
        ski_extension = calculate_spki_hash(cert, "SHA1")

    if not ski_extension:
        ski_extension = calculate_spki_hash(cert, "SHA1")

    return ski_extension

def get_akid(cert):
    """Extract Authority Key Identifier."""
    return get_extension_value(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER, 'key_identifier')

def fetch_issuer_certificate(cert: x509.Certificate) -> x509.Certificate | None:
    """
    Extracts the CA Issuer URL from the AIA extension (if present),
    downloads the certificate, and returns it as an x509.Certificate object.
    Supports DER, PEM, and PKCS#7 (.p7b) encoded responses.
    Returns None if no issuer cert is present or downloadable.
    """

    #from asn1crypto import cms, pem

    try:
        aia = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        logging.warning("No AIA extension found.")
        return None

    ca_issuer_urls = [
        desc.access_location.value
        for desc in aia
        if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS
    ]

    logging.debug(f'Extracted AIA value(s) from certificate as: {ca_issuer_urls} ')

    if not ca_issuer_urls:
        logging.warning("No CA Issuers entry found in AIA.")
        return None

    for url in ca_issuer_urls:
        logging.info(f"Attempting to download Issuing CA certificate from: {url}")

        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except Exception as e:
            logging.error(f"Failed to download Issuing CA certificate: {e}")
            return None

        data = response.content

        # Try to load as DER
        try:
            c = x509.load_der_x509_certificate(data)
            if c.subject == cert.issuer:
                return c
        except Exception:
            pass

        # Try to load as PEM
        try:
            c = x509.load_pem_x509_certificate(data)
            if c.subject == cert.issuer:
                return c
        except Exception:
            pass

        # Try to load as PKCS#7 (PEM)
        try:
            pkcs7_certs = pkcs7.load_pem_pkcs7_certificates(data)
            for c in pkcs7_certs:
                if c.subject == cert.issuer:
                    return c
        except Exception:
            pass

        # Try to load as PKCS#7 (DER)
        try:
            pkcs7_certs = pkcs7.load_der_pkcs7_certificates(data)
            for c in pkcs7_certs:
                if c.subject == cert.issuer:
                    return c
        except Exception:
            pass

    logging.error("No matching issuer certificate could be fetched.")
    return None
