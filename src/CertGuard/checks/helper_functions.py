import certifi
import logging
import os
import sqlite3
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from glob import glob
from mitmproxy import http
from requests_cache import CachedSession
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

    with open('logs/!trusted_roots.txt', 'w') as f:
        for root in roots:
            f.write(root.subject.rfc4514_string() + '\n')
        logging.info(f'List of trusted roots for this session exported to logs/trusted_roots.txt.')

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

def record_decision(db_path, host, decision, root_fingerprint) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute("REPLACE INTO decisions (host, decision, root, timestamp) VALUES (?, ?, ?, ?)", (host, decision, root_fingerprint, now))
        conn.commit()
