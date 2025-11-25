import certifi
import hashlib
import logging
import os
import sqlite3
import sys
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
#from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta, timezone
#from enum import Enum
from mitmproxy import http
from requests_cache import CachedSession, timedelta
#from typing import Sequence
from urllib.parse import urlparse

def is_navigation_request(flow: http.HTTPFlow, referer_header, accept_header) -> bool:
    logging.debug(f"----------------------------------Entering is_navigation_request()-------------------------------")
    method = flow.request.method.upper()
    
    # Only consider GET/POST requests that want HTML
    if method not in ("GET", "POST"):
        logging.info(f"Method not GET or POST; returning False.")
        return False

    # Heuristic 1: Initial navigation 
    if not referer_header:   # No Referer = likely main navigation (or privacy browser extension that strips it out)
        logging.info(f"No referer header found; assuming new navigation.")
        return True

    # Heuristic 2: Cross-origin navigation
    referer_hostname = urlparse(referer_header).hostname
    logging.debug(f"Hostname from referer_header:   {referer_hostname}")
    #logging.debug(f"From flow.request.pretty_host:  {flow.request.pretty_host}")
    logging.debug(f"Hostname from flow.request:     {flow.request.host}")
    if (referer_hostname != flow.request.pretty_host) and "text/html" in accept_header:
        logging.info(f"Hostname from referer_header ({urlparse(referer_header).hostname} doesn't match flow host ({flow.request.pretty_host}),")
        logging.info(f"but request accepts HTML responses, so assuming cross-origin browser navigation.")
        return True

    # Heuristic 3: Fetch destination
    dest = flow.request.headers.get("sec-fetch-dest", None)
    if dest == "document":
        logging.info("sec-fetch-dest header has destination of 'document'; assuming browser navigation & returning True.")
        return True

    # Heuristic 4: Accept header
    accept = flow.request.headers.get("accept", "")
    if "text/html" in accept:
        logging.info("Found 'text/html' in Accept: header; returning True.")
        return True
    
    logging.info(f"Could not ascertain new browser navigation; returning False.")
    return False

def get_root_store(custom_roots_dir) -> list[x509.Certificate]:
    """
    Loads trusted root certificates from local certifi store, along with any defined custom roots.

    Args:
        None
    
    Returns:
        roots (list): List of cryptography.x509.Certificate objects for each root certificate enumerated.
    """
    if not os.path.exists(certifi.where()):
        logging.critical(f"FATAL Error: Cannot locate certifi store at {certifi.where()}. Try updating the 'certifi' package for your OS!")
        sys.exit()
    else:
        logging.info(f'Using certifi package located at {certifi.where()} as base root CA store.')
    
    with open(certifi.where(), "rb") as f:
        root_bundle = f.read()
        base_count = root_bundle.count(b'END CERTIFICATE')
        logging.debug(f'Loaded {base_count} certificates from {certifi.where()}.')

    # Load custom root CA certs
    if custom_roots_dir != None:
        from glob import glob
        if os.path.isdir(custom_roots_dir):
            pem_files = glob(os.path.join(custom_roots_dir, '*.pem'))
            logging.info(f'Loading {len(pem_files)} custom root files from {custom_roots_dir}.')
            for file in pem_files:
                with open(file, "rb") as f:
                    root_bundle += f.read()
        else:
            logging.critical(f"Could not find directory specified for 'custom_roots_dir': {custom_roots_dir}.")
            logging.critical(f"Please check configuration in config.toml file or create/populate custom roots directory.")

    roots: list[x509.Certificate] = []
    for pem_block in root_bundle.split(b"-----END CERTIFICATE-----"):
        pem_block = pem_block.strip()
        if pem_block:
            pem_block += b"\n-----END CERTIFICATE-----\n"
            try:
                roots.append(x509.load_pem_x509_certificate(pem_block, default_backend()))
            except Exception:
                pass
    logging.info(f'Total root certificates loaded: {len(roots)}')
    return roots

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
    Loads the Public Suffix List maintained by Mozilla from https://publicsuffix.org/list/public_suffix_list.dat.
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

def get_cert_domains(x509_cert: x509.Certificate) -> list[str]:
    """
    Extract CN and DNS SubAltNames from a mitmproxy.certs.Cert object.

    Args:
        x509_cert: A x509.Certificate object containing the certificate to extract FQDNs from.

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

def is_self_signed(cert: x509.Certificate) -> bool:
    """
    Return True if a certificate is self-signed.
    """
    from chain_builder import verify_signature
    
    # A self-signed cert must have identical subject and issuer.
    if cert.subject != cert.issuer:
        return False
    # Verify the signature using the certificate's own public key.
    try:
        verify_signature(cert, cert)
        return True
    except Exception as e:
        logging.error(f'Exception encountered while verifying self-signed cert digital signature verification.')
        return False

def chain_terminates_in_root(chain: list[x509.Certificate]) -> bool:
    """
    Given an ordered list of x509.Certificate objects (leaf -> root),
    return True if the last certificate is a self-signed root.
    """
    if not chain:
        return False

    last_cert = chain[-1]
    return is_self_signed(last_cert)

def calculate_spki_hash(cert: x509.Certificate, hash_type: str, hex: bool = False) -> str:
    """
    Calculates a hash against the provided certificate's Subject Public Key Information (SPKI) data.
    
    Args:
        cert:           An x509.Certificate object from the cryptography library.
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

def clean_error(html_string: str) -> str:
    """Strips HTML tags using lxml and removes unicode characters to produce text-only error."""
    from lxml.html import fromstring
    import re

    cz_to_replace = r"🛈|ℹ️|✅|✘|❌|⛔|⚠️|▶|&nbsp;|&emsp;"
    
    error_text = re.sub(cz_to_replace, '', html_string).strip()
    tree = fromstring(error_text)
    clean_error_text = tree.text_content()
    
    return clean_error_text

def record_decision(db_path, host, decision, root_fingerprint) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute("REPLACE INTO decisions (host, decision, root, timestamp) VALUES (?, ?, ?, ?)", (host, decision, root_fingerprint, now))
        conn.commit()

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import AuthorityInformationAccessOID

def fetch_issuer_certificate(cert: x509.Certificate) -> x509.Certificate | None:
    """
    Extracts the CA Issuer URL from the AIA extension (if present),
    downloads the certificate, and returns it as an x509.Certificate object.
    Returns None if no issuer cert is present or downloadable.
    """

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

    if not ca_issuer_urls:
        logging.warning("No CA Issuers entry found in AIA.")
        return None

    issuer_url = ca_issuer_urls[0]
    logging.info(f"Downloading Issuing CA certificate from: {issuer_url}")

    try:
        response = requests.get(issuer_url, timeout=5)
        response.raise_for_status()
    except Exception as e:
        logging.error(f"Failed to download Issuing CA certificate: {e}")
        return None

    data = response.content

    # Try to load as DER
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        pass

    # Try to load as PEM
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        pass

    logging.error("Downloaded Issuer certificate could not be parsed as DER or PEM.")
    return None