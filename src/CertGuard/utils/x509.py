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

def get_skid(cert):
    """Extract Subject Public Key Identifier (SKI) if present, else calculate it as SHA1 hash of Subject Public Key Information (SPKI)."""
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

def fetch_issuer_certificate(cert: x509.Certificate, already_fetched_certs:list[x509.Certificate] = None) -> x509.Certificate | None:
    """
    Extracts the CA Issuer URL from the AIA extension (if present),
    downloads the certificate, and returns it as an x509.Certificate object.
    Supports DER, PEM, and PKCS#7 (.p7b/.p7c) encoded responses.
    Returns None if no issuer cert is present or downloadable.
    """
    logging.warning(f"-----------------------------------Entering fetch_issuer_certificate()----------------------------")
    
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
        return None

    for url in ca_issuer_urls:
        logging.info(f"Attempting to download Issuing CA certificate from: {url}")

        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except Exception as e:
            logging.error(f"Failed to download Issuing CA certificate: {e}")
            return None

        fetched_file = response.content


    is_pem = fetched_file.strip().startswith(b"-----BEGIN")

    # Try loading single cert first
    try:
        if is_pem:
            c = x509.load_pem_x509_certificate(fetched_file)
        else:
            c = x509.load_der_x509_certificate(fetched_file)
        return c
    except Exception:
        pass

    # Try to load as PKCS#7 bundled certificates
    logging.info('Attempting to extract issuer cert from PKCS#7 bundle.')
    aki_to_match = get_akid(cert)

    try:
        if is_pem:
            pkcs7_certs = pkcs7.load_pem_pkcs7_certificates(fetched_file)
        else:
            pkcs7_certs = pkcs7.load_der_pkcs7_certificates(fetched_file)
    except Exception:
        logging.error("No matching issuer certificate could be fetched.")
        return None

    if pkcs7_certs:
        for c in pkcs7_certs:
            #logging.debug(f'fetched cert SKID:       {get_skid(c)}')
            #logging.debug(f'trying match against     {aki_to_match}')
            #logging.debug(f'fetched cert subject:    {c.subject.rfc4514_string()}')
            #logging.debug(f'trying to match against: {cert.issuer.rfc4514_string()}')
            if (
                get_skid(c) == aki_to_match and 
                c.subject == cert.issuer and 
                c not in (already_fetched_certs or [])
            ):
                return c
    else:
        logging.error("No matching issuer certificate could be fetched.")
        return None

def load_pkcs7_data(pkcs7):
    """Load certs from PKCS#7 bundle file. Attempt PEM format first, and fall back to DER if necessary"""
    loaders = [pkcs7.load_pem_pkcs7_certificates, pkcs7.load_der_pkcs7_certificates]
    for loader in loaders:
        try:
            return loader(pkcs7)
        except Exception:
            continue
    return None