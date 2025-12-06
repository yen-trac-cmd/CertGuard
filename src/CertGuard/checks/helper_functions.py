import certifi
import logging
import os
import sqlite3
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta, timezone
from glob import glob
from mitmproxy import http
from requests_cache import CachedSession
from typing import Tuple
from urllib.parse import urlparse

def is_navigation_request(flow: http.HTTPFlow, referer_header, accept_header) -> bool:
    logging.warning(f"----------------------------------Entering is_navigation_request()-------------------------------")
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

def load_pem_bundle(dir_path: str, label: str) -> bytes:
    """
    Load all .pem files from a directory into a single bytes bundle.
    Logs status/error messages consistently.
    """
    if not dir_path:
        return b""

    if not os.path.isdir(dir_path):
        logging.critical(f"Could not find directory specified for '{label}': {dir_path}.")
        logging.critical("Please check configuration in config.toml or create/populate the directory.")
        return b""

    pem_files = glob(os.path.join(dir_path, "*.pem"))
    logging.info(f"Loading {len(pem_files)} {label} files from {dir_path}.")

    bundle = b""
    for file in pem_files:
        with open(file, "rb") as f:
            bundle += f.read()

    return bundle

def parse_pem_bundle(bundle: bytes, label: str) -> list[x509.Certificate]:
    """
    Parse a concatenated PEM bundle containing multiple certificates.
    Returns a list of x509.Certificate objects.
    """
    if not bundle:
        logging.info(f"No {label} certificates found.")
        return []

    certs: list[x509.Certificate] = []

    for block in bundle.split(b"-----END CERTIFICATE-----"):
        block = block.strip()
        if not block:
            continue

        pem = block + b"\n-----END CERTIFICATE-----\n"

        try:
            certs.append(x509.load_pem_x509_certificate(pem, default_backend()))
        except Exception as e:
            logging.error(f'Encountered exception while parsing PEM cert data: {e}')
            pass

    return certs

def get_cert_stores(custom_roots_dir: str, deprecated_dir: str, custom_ints_dir: str) -> Tuple[list[x509.Certificate], list[x509.Certificate]]:
    """
    Loads trusted root certificates from local certifi store, along with any defined custom CA root/intermediate certs.

    Args:
        custom_roots_dir:     Directory for additional root CA certs to load beyond what ships in Certifi bundle.
        deprecated_dir:       Directory for valid, but deprecated root CA certs that can be enumerated from AIA fetching or included in server cert chains.
        custom_ints_dir:      Directory for additional intermediate CA certs to load.  
                              (Sometimes required for servers that fail to send complete certificate chains)
    Returns:
        roots:          List of cryptography.x509.Certificate objects for each root CA certificate enumerated.
        deps:           List of cryptography.x509.Certificate objects for each deprecated root CA certificate enumerated.
        ints:           List of cryptography.x509.Certificate objects for each intermediate CA certificate enumerated.
    """

    # Load Certifi bundle as starting point for root store
    if not os.path.exists(certifi.where()):
        logging.critical(f"FATAL Error: Cannot locate certifi store at {certifi.where()}. Try updating the 'certifi' package for your OS!")
        sys.exit()
    else:
        logging.info(f'Using certifi package located at {certifi.where()} as base root CA store.')
    
    with open(certifi.where(), "rb") as f:
        root_bundle = f.read()
        base_count = root_bundle.count(b'END CERTIFICATE')
        logging.debug(f'Loaded {base_count} certificates from {certifi.where()}.')

    # Load PEM-encoded certs from disk
    custom_root_bundle = load_pem_bundle(custom_roots_dir, "custom root CA cert")
    deprecated_bundle = load_pem_bundle(deprecated_dir, "deprecated CA cert")
    int_bundle  = load_pem_bundle(custom_ints_dir, "custom intermediate CA cert")
    
    combined_roots = root_bundle + custom_root_bundle

    # Load the PEM data into lists of x509.Certificate objects
    roots = parse_pem_bundle(combined_roots, "root CA")
    deps  = parse_pem_bundle(deprecated_bundle, "deprecated CA")
    ints  = parse_pem_bundle(int_bundle, "intermediate CA")

    # Build list for exporting root subjects & fingerprints to '_trusted_roots.txt' reference file.
    root_entries = []
    for cert in roots:
        sha256_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        subject = cert.subject.rfc4514_string()
        root_entries.append((subject, sha256_fingerprint))

    # Sort alphabetically by subject for easier lookup
    root_entries.sort(key=lambda x: x[0])

    with open('logs/_trusted_roots.txt', 'w', encoding='utf-8') as f:
        for subject, sha256_fingerprint in root_entries:
            f.write(f'{sha256_fingerprint}, {subject}\n')
        logging.info(f'List of trusted roots for this session exported to logs/trusted_roots.txt.')

    return roots, deps, ints

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

def is_self_signed(cert: x509.Certificate) -> bool:
    """
    Return True if a certificate is self-signed.
    """
    from checks.chain_builder import verify_signature
    
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
    return True if the last certificate is self-signed.
    """
    if not chain:
        return False

    last_cert = chain[-1]
    return is_self_signed(last_cert)

def clean_error(html_string: str) -> str:
    """Strips HTML tags using lxml and removes unicode characters to produce text-only error."""
    from lxml.html import fromstring
    import re

    cz_to_replace = r"🛈|ℹ️|✅|✘|❌|⛔|⚠️|🎉|▶|&nbsp;|&emsp;"
    
    error_text = re.sub(cz_to_replace, '', html_string).strip()
    tree = fromstring(error_text)
    clean_error_text = tree.text_content()
    
    return clean_error_text

def record_decision(db_path, host, decision, root_fingerprint, root_subject, root_expiry, tag) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            REPLACE INTO decisions 
                (host, decision, root_hash, subject, expiry, tag, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, 
            (host, decision, root_fingerprint, root_subject, root_expiry, tag, now)
        )
        conn.commit()
