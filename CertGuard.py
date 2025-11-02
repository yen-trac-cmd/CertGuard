from ca_org_mapping import ca_org_to_caa
from CertGuardConfig import Config, ErrorLevel
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa, padding
from cryptography.x509.extensions import SubjectKeyIdentifier
from dane import DANETLSAValidator
from datetime import datetime, timedelta, timezone
from dns.rdtypes.ANY import CAA
from dns.resolver import dns
from error_screen import error_screen
from helper_functions import calculate_ski, get_cert_domains, supported_ciphers_list
from logging.handlers import RotatingFileHandler
from mitmproxy import ctx, http, addonmanager
from tls_extensions import OCSPStaplingConfig
from typing import Sequence, Optional, Tuple
from urllib.parse import urlparse
import certifi
import logging  # Valid levels = debug, info, warning, error, critical, fatal.  
import os
import revocation_logic
import sqlite3
import sys
import uuid
import verify_SCTs

CONFIG = Config()
BYPASS_PARAM = "CertGuard-Token"

def load(loader: addonmanager.Loader) -> None:
    """
    Sets mitmproxy logging level & TLS protocol support, and creates CertGuard database if not present.
    """
    if CONFIG.logging_level in ["debug", "info", "warn", "error", "alert"]:
        opts = ctx.options.keys()
        if "console_eventlog_verbosity" in opts:
            # Running in mitmproxy console UI
            logging.info("Detected mitmproxy console UI")
            ctx.options.console_eventlog_verbosity = CONFIG.logging_level
        else:
            # Running in mitmdump (or mitmweb)
            logging.info("Detected mitmdump/mitmweb")
            ctx.options.termlog_verbosity = CONFIG.logging_level
    else:
        logging.warning(f"Invalid console logging mode defined in config.toml; defaulting to 'info' level.")
    

    #######################################################################TESTING#################################################
    LOG_FILE = "logfile.log"
    LOG_FORMAT = '%(asctime)s.%(msecs)03d %(name)s %(levelname)s %(message)s'
    formatter = logging.Formatter(LOG_FORMAT)
    formatter.datefmt = '%Y%m%d_%H:%M:%S'
    
    # Create a file handler (e.g., RotatingFileHandler for log rotation)
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1048576*5, backupCount=7)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG) 
        
    logger = logging.getLogger('CertGuard')
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == file_handler.baseFilename for h in logger.handlers):
        logger.addHandler(file_handler)
    
    logging.info(f"Logging to {LOG_FILE}.")
    '''
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logfile = os.path.join(os.getcwd(), "logfile.log")
    handler = logging.FileHandler(logfile)
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == handler.baseFilename for h in logger.handlers):
        logger.addHandler(handler)

    #logging.basicConfig(level=logging.DEBUG, format='"%(asctime)s [%(name)s] %(levelname)s: %(message)s"', filename=logfile, filemode='a')
    logger.info('GGGAAAAAAAAAAAAAAAAAAAAAAAAAA request made from module: %s', __name__)
    '''
    #######################################################################TESTING#################################################
    

    match CONFIG.min_tls_version:
        case 1.0:
            ctx.options.tls_version_server_min = "TLS1"
        case 1.1:
            ctx.options.tls_version_server_min = "TLS1_1"
        case 1.2:
            ctx.options.tls_version_server_min = "TLS1_2"
        case 1.3:
            ctx.options.tls_version_server_min = "TLS1_3"
        case _:
            ctx.options.tls_version_server_min = "TLS1_2"
    logging.debug(f'Minimum TLS version for upstream connection set to {ctx.options.tls_version_server_min}.')

    if CONFIG.ciphersuites != None:
        supported_ciphers = supported_ciphers_list()
        target_ciphers = []
        for cipher in CONFIG.ciphersuites.split(':'):
            if cipher in supported_ciphers:
                target_ciphers.append(cipher)
        ctx.options.ciphers_server = ":".join(target_ciphers)
        logging.debug(f'Configured ciphers: \n* {"\n* ".join(target_ciphers)}')

    # Create SQLite DB and table if not exists
    with sqlite3.connect(CONFIG.db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                host TEXT PRIMARY KEY,
                decision TEXT,
                root TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()

    logging.warning(f"===> Reloaded CertGuard Addon")

def get_root_store() -> list[x509.Certificate]:
    """
    Loads trusted root certificates from local certifi store, along with any defined custom roots.

    Args:
        None
    
    Returns:
        roots (list): List of cryptography.x509.Certificate objects for each root certificate enumerated.
    """
    if not os.path.exists(certifi.where()):
        logging.fatal(f"FATAL Error: Cannot locate certifi store at {certifi.where()}. Try updating the 'certifi' package for your OS!")
        sys.exit()
    else:
        logging.info(f'Using certifi package located at {certifi.where()} as base root CA store.')
    
    with open(certifi.where(), "rb") as f:
        root_bundle = f.read()
        base_count = root_bundle.count(b'END CERTIFICATE')
        logging.debug(f'Loaded {base_count} certificates from {certifi.where()}.')

    # Load custom root CA certs
    if CONFIG.custom_roots_dir != None:
        from glob import glob
        if os.path.isdir(CONFIG.custom_roots_dir):
            pem_files = glob(os.path.join(CONFIG.custom_roots_dir, '*.pem'))
            logging.info(f'Loading {len(pem_files)} custom root files from {CONFIG.custom_roots_dir}.')
            for file in pem_files:
                with open(file, "rb") as f:
                    root_bundle += f.read()
        else:
            logging.fatal(f"Could not find directory specified for 'custom_roots_dir': {CONFIG.custom_roots_dir}.")
            logging.fatal(f"Please check configuration in config.toml file or create/populate custom roots directory.")

    roots = []
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

def is_navigation_request(flow: http.HTTPFlow, referer_header, accept_header) -> bool:
    logging.debug(f"-----------------------------------Entering is_navigation_request()----------------------------------------")
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
    logging.debug(f"Hostname from referer_header: {referer_hostname}")
    logging.debug(f"Hostname from flow.request:   {flow.request.pretty_host}")
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

def get_root_cert(server_chain: Sequence[x509.Certificate], root_store: Sequence[x509.Certificate]) -> Tuple[Optional[x509.Certificate], Optional[str]]:
    """
    Given an x509.Certificate chain and trusted root store, attempt to resolve and verify the root CA certificate for the server's certificate chain.

    Args:
        chain (Sequence): Ordered x509 certificate chain presented by the server (leaf first, intermediates, and optionally a root cert)
        root_store (Sequence[x509.Certificate]): List of trusted root certificates to match against.
    Returns:
        Tuple[Optional[x509.Certificate], Optional[str]]: (root_cert, identifier)
            root_cert: matched root cert from root_store, or None if no match.
            identifier: CN (preferred) or full RFC 4514 subject string of the matched root cert, or None if no root identified.
    """
    logging.warning(f"-----------------------------------Entering get_root_cert()------------------------------------------")
    logging.info(f'Number of certifi + custom trusted root CA entries: {len(root_store)}')

    # Verify each link in the chain, starting from leaf and working up to the last interemediate CA cert
    for issuer, subject in zip(server_chain[1:], server_chain[:-1]):
        try:
            verify_signature(subject, issuer)
            logging.info(f"Signature verification for {subject.subject.rfc4514_string()} successful.")
        except Exception as e:
            logging.critical(f"Initial chain verification failed between '{subject.subject.rfc4514_string()}' and '{issuer.subject.rfc4514_string()}': {e}")
            logging.critical(f"Aborting further verification attempts.")
            return None, None
            
    # If using self-signed cert...
    if len(server_chain) == 1:
        self_signed = server_chain[0].issuer.rfc4514_string()
        logging.error(f'Self-signed certificate; Subject = {self_signed}')
        return None, self_signed

    logging.info(f'Length of presented chain:       {len(server_chain)}')
    labels = ["LEAF cert", "Issuing CA", "Subordinate CA"]

    for i, cert in enumerate(server_chain):
        # Label selection logic
        if i == 0:
            label = "LEAF cert"
        elif cert.subject == cert.issuer:
            label = "Root cert"
        elif i == 1:
            label = "Issuing CA"
        else:
            label = f"Subordinate CA #{i-1}" if i > 2 else "Subordinate CA"
        
        try:
            ski_extension = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex()
        except x509.ExtensionNotFound:
            ski_extension = calculate_ski(cert)

        fields = {
            "Subject": cert.subject.rfc4514_string(),
            "Issuer": cert.issuer.rfc4514_string(),
            "Serial number": cert.serial_number,
            "Serial number (hex)": hex(cert.serial_number),
            "Not valid before UTC": cert.not_valid_before_utc,
            "Not valid after UTC": cert.not_valid_after_utc,
            "Subject Key ID (SKI)": ski_extension,
            "Fingerprint (SHA1)": cert.fingerprint(hashes.SHA1()).hex(),
            "Fingerprint (SHA256)": cert.fingerprint(hashes.SHA256()).hex(),            
        }
        
        # Compute padding width (based on longest field name)
        max_key_len = max(len(k) for k in fields)
        pad = max_key_len + 2

        logging.warning(f"{label}:")
        for key, value in fields.items():
            prefix = f"  {key + ':':<{pad}}"
            logging.info(f"{prefix}{value}")

    # Verify last cert in chain against a trusted root anchors 
    last_cert = server_chain[-1]
    for root in root_store:
        if root.subject == last_cert.issuer:
            try:
                verify_signature(last_cert, root)
                logging.warning('Chain verified against Root CA:')
                logging.info  (f'  Subject:              {root.subject.rfc4514_string()}')
                logging.info  (f'  Issuer:               {root.issuer.rfc4514_string()}')
                logging.info  (f'  Serial number:        {root.serial_number}')
                logging.info  (f'  Serial number (hex):  {hex(root.serial_number)}')
                logging.info  (f'  Not valid before UTC: {root.not_valid_before_utc}')
                logging.info  (f'  Not valid after UTC:  {root.not_valid_after_utc}')
                logging.info  (f'  Subject Key ID (SKI): {calculate_ski(root)}')
                logging.info  (f'  Fingerprint (SHA1):   {(root.fingerprint(hashes.SHA1())).hex()}')
                logging.info  (f'  Fingerprint (SHA256): {(root.fingerprint(hashes.SHA256())).hex()}')
                return root, None
            except Exception as e:
                logging.fatal(f"Root CA cert verification failed: {e}")
                continue
    
    logging.fatal(f"No trust anchor cert found!")

    try:
        return None, last_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except:
        return None, last_cert.issuer.rfc4514_string()

def verify_signature(subject: x509.Certificate, issuer: x509.Certificate) -> None:
    """
    Cryptographically verify that `issuer` signed `subject`.
    
    Handles RSA (PKCS#1 v1.5 and basic PSS), ECDSA, Ed25519/Ed448, and DSA.
    """
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
            pub.verify(
                signature=subject.signature,
                data=subject.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=h,
            )

    elif isinstance(pub, ec.EllipticCurvePublicKey):
        # ECDSA takes a signature algorithm wrapper with the hash
        pub.verify(
            signature=subject.signature,
            data=subject.tbs_certificate_bytes,
            signature_algorithm=ec.ECDSA(h),
        )

    elif isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(subject.signature, subject.tbs_certificate_bytes)

    elif isinstance(pub, ed448.Ed448PublicKey):
        pub.verify(subject.signature, subject.tbs_certificate_bytes)

    elif isinstance(pub, dsa.DSAPublicKey):
        pub.verify(
            signature=subject.signature,
            data=subject.tbs_certificate_bytes,
            algorithm=h,
        )

    else:
        raise TypeError(f"Unsupported public key type: {type(pub)}")

def root_country_check(flow: http.HTTPFlow, root: x509.Certificate) -> Tuple[ErrorLevel, Optional[str]]:
    """
    Check the country of the root CA certificate for a mitmproxy HTTP flow to see if it's blocked or allowed (depending on user configuration).

    Args:
        flow (mitmproxy.http.HTTPFlow): The HTTP flow representing a single HTTP transaction.
        root (x509.Certificate): The root CA certificate to check.

    Returns:
        Tuple[ErrorLevel, Optional[str]]: 
            ErrorLevel: Enum indicating severity of check results.
            Optional[str]: Description of country violation, or None if not applicable.
    """
    logging.warning(f"-----------------------------------Entering root_country_check()------------------------------------------")
    logging.info(f'Root certificate subject:        {root.subject.rfc4514_string()}')

    root_country = root.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)
    if len(root_country) == 0:
        logging.warning(f"==>> No Country value found in Root CA cert: {root.subject.rfc4514_string()}")  # 
        violation = f'ℹ️ No Country (C=) value found in Root CA cert: <b>{root.subject.rfc4514_string()}</b>'
        return ErrorLevel.NOTICE, violation
    elif len(root_country) > 1:
        logging.fatal(f"==>> Multiple Country values found in Root CA cert: {root.subject.rfc4514_string()}")
        violation = f"⛔ Multiple Country (C=) values found in Root CA cert: <b>{root.subject.rfc4514_string()}</b>"
        return ErrorLevel.FATAL, violation
    else:
        root_country=root_country[0].value
        logging.info(f"Country attribute for root:      {root_country} ")

        if root_country in CONFIG.blocklist:
            violation = f"⛔ Root CA is located in a <b style='color:red;'>blocklisted</b> country: <b>{CONFIG.iso_country_map[root_country]}</b>"
            logging.error(f'Root CA for {flow.request.pretty_url} is located in a blocklisted country: {CONFIG.iso_country_map[root_country]}')
            return ErrorLevel.FATAL, violation

        if (CONFIG.filtering_mode == 'allow' and root_country not in CONFIG.country_list) or (CONFIG.filtering_mode == 'warn' and root_country in CONFIG.country_list):
            violation = f"⚠️ Root CA is located in <strong>{CONFIG.iso_country_map[root_country]}</strong>."
            logging.warning(f'Root CA is located in: {CONFIG.iso_country_map[root_country]}')
            return ErrorLevel.CRIT, violation
            
    return ErrorLevel.NONE, None

def controlled_CA_checks(flow: http.HTTPFlow, root: x509.Certificate) -> tuple["ErrorLevel", Optional[str]]:
    """
    Perform controlled certificate authority (CA) checks on the provided root certificate.
    
    This function inspects the subject fields of the root CA (Common Name, Organization,
    and full Distinguished Name) and compares them against configured lists of
    prohibited and restricted root issuers defined in the `config.toml` file.

    ### Args:
        - flow (mitmproxy.http.HTTPFlow):
            - The mitmproxy HTTP flow associated with the current transaction, but not 
            actually used by controlled_CA_checks().
        - root (x509.Certificate):
            - The root CA certificate presented by the server.

    ### Returns:
        - tuple[ErrorLevel, Optional[str]]:
        A two-element tuple `(ErrorLevel, message)` indicating the result of the check.
            - `ErrorLevel.FATAL`, message — if the root CA is explicitly prohibited.
            - `ErrorLevel.CRIT`, message — if the root CA is restricted.
            - `ErrorLevel.NONE`, `None` — if no restrictions or violations are detected.
    """
    
    logging.warning(f"-----------------------------------Entering controlled_CA_checks()----------------------------------------")
    identifiers=[]
    
    root_cn = root.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if root_cn:
        identifiers.append(root_cn[0].value)
    
    root_org = root.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
    if root_org:
        identifiers.append(root_org[0].value)

    root_dn = root.subject.rfc4514_string()
    logging.debug(f"Root DN value:                   {root_dn}")
    
    prohibited_value = set(identifiers) & set(CONFIG.prohibited_roots)
    restricted_value = set(identifiers) & set(CONFIG.restricted_roots)
    
    if prohibited_value:
        violation = f"⛔ Prohibited Root CA detected: <b>{list(prohibited_value)[0]}</b>"
        logging.fatal(f'Prohibited Root CA detected: {list(prohibited_value)[0]}')
        return ErrorLevel.FATAL, violation
    elif restricted_value:
        violation = f"⚠️ Restricted Root CA detected: <b>{list(restricted_value)[0]}</b>"
        logging.fatal(f"Restricted Root CA detected: '{list(restricted_value)[0]}', issued by {root_org[0].value}.")
        return ErrorLevel.CRIT, violation
    return ErrorLevel.NONE, None

def expiry_check(flow: http.HTTPFlow, root: x509.Certificate) -> Tuple[ErrorLevel, Optional[str]]:

    """Check if any certificate in the chain is expired."""
    logging.warning("-----------------------------------Entering expiry_check()----------------------------------------")

    # Build cert chain provided by server
    cert_chain = [cert.to_cryptography() for cert in flow.server_conn.certificate_list] 
    
    # Add root cert to complete the chain, provided that it's not already supplied in the chain.
    if not cert_chain[-1].subject == cert_chain[-1].issuer:
        cert_chain.append(root)

    now = datetime.now(timezone.utc)
    chain_length = len(cert_chain)
    expired = []

    for i, cert in enumerate(cert_chain, start=1):
        not_after = cert.not_valid_after_utc
        if now > not_after:
            cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            cn = cn_attrs[0].value if cn_attrs else cert.subject.rfc4514_string()
            expiry = not_after.strftime("%Y-%m-%d")
            logging.error(f"Found expired cert: {cn} at chain position {i}")
            expired.append((i, cn, expiry))

    if not expired:
        logging.debug('No expired certs found in cert chain.')
        return ErrorLevel.NONE, None

    def label_for_position(pos: int) -> str:
        if pos == 1:
            return "Leaf cert"
        if pos == 2:
            return "Issuing CA"
        if pos == chain_length:
            return "Root"
        return "Subordinate"

    violations = [
        f'&emsp;&emsp;▶ {label_for_position(i)} <code>{cn}</code> expired on {exp}'
        for i, cn, exp in expired
    ]

    error_message = f'⚠️ Expired certificate(s) identified:<br>{"<br>".join(violations)}'
    return ErrorLevel.CRIT, error_message   

def revocation_checks(flow: http.HTTPFlow, root: x509.Certificate) -> Tuple[ErrorLevel, Optional[str]]:
    """
    Facade function for performing revocation checking against certificates.
    """
    if not CONFIG.revocation_checks:
        logging.warning("Skipping revocation checks per 'revocation_checks' configuration directive.")
        return ErrorLevel.NONE, None
    
    # Build cert chain provided by server
    cert_chain = [cert.to_cryptography() for cert in flow.server_conn.certificate_list] 
    
    # Add root cert to complete the chain, provided that it's not already supplied in the chain.
    if not cert_chain[-1].subject == cert_chain[-1].issuer:
        cert_chain.append(root)

    # Check for OCSP data in flow metadata
    skip_leaf = False
    if flow.metadata.get("ocsp_signature_valid") and flow.metadata.get("ocsp_cert_status") == "GOOD":
        # If stapled OCSP response attached to flow, skip_leaf argument to check_cert_chain_revocation() will skip revocation checking for leaf cert.
        skip_leaf = True

    is_revoked, error = revocation_logic.check_cert_chain_revocation(cert_chain, skip_leaf)
    if is_revoked:
        logging.error(f'One or more certificates REVOKED!')
        violation = f"⛔ One or more certs in chain marked as REVOKED:{error}"
        return ErrorLevel.FATAL, violation

    if not error:
        return ErrorLevel.NONE, None

    return ErrorLevel.INFO, error

def identity_check(flow: http.HTTPFlow, root: x509.Certificate) -> Tuple[ErrorLevel, Optional[str]]:
    """Check if any certificate in the chain lacks a subject, or if the leaf cert lacks a SAN."""
    logging.warning("-----------------------------------Entering identity_check()----------------------------------------")

    # Build full cert chain from leaf to root
    cert_chain = [cert.to_cryptography() for cert in flow.server_conn.certificate_list] + [root]
    chain_length = len(cert_chain)
    violations = []

    def label_for_position(pos: int) -> str:
        if pos == 1:
            return "Leaf cert"
        if pos == 2:
            return "Issuing CA cert"
        if pos == chain_length:
            return "Root"
        return "Subordinate"

    for i, cert in enumerate(cert_chain, start=1):
        label = label_for_position(i)
        cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cn = cn_attrs[0].value if cn_attrs else cert.subject.rfc4514_string() or "(no subject)"
        subject_missing = not cert.subject or len(cert.subject) == 0
        san_missing = False

        # Only check SAN for the leaf certificate
        if i == 1:
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san_entries = san_ext.value.get_values_for_type(x509.DNSName)
                san_missing = len(san_entries) == 0
            except x509.ExtensionNotFound:
                san_missing = True

        # Collect any violations
        if subject_missing or san_missing:
            logging.error(
                f"{label} ({cn}) is missing "
                f"{'subject' if subject_missing else ''}"
                f"{' and ' if subject_missing and san_missing else ''}"
                f"{'SAN' if san_missing else ''}."
            )

            if subject_missing and san_missing:
                violations.append(f'&emsp;&emsp;▶ {label} <code>{cn}</code> missing both Subject and SAN fields.')
            elif subject_missing:
                violations.append(f'&emsp;&emsp;▶ {label} <code>{cn}</code> missing Subject field.')
            elif san_missing:
                violations.append(f'&emsp;&emsp;▶ {label} <code>{cn}</code> missing Subject Alternative Name (SAN).')

    if not violations:
        logging.debug('Cert identity checks completed successfully.')
        return ErrorLevel.NONE, None

    error_message = f'⚠️ Identity issue(s) found in certificate chain:<br>{"<br>".join(violations)}'
    return ErrorLevel.CRIT, error_message

def prior_approval_check(flow: http.HTTPFlow, root_cert: x509.Certificate, quick_check: bool =False) -> bool | tuple[ErrorLevel, Optional[str]]:
    """
    Check whether the given host and root certificate have been previously approved,
    or if a root CA change has occurred since the last recorded decision.

    This function consults the local SQLite database to determine whether the
    host has a prior approval record and whether the associated root certificate
    fingerprint matches the stored record.

    Args:
        flow (mitmproxy.http.HTTPFlow):
            The mitmproxy HTTP flow representing the transaction (used to extract the host).
        root_cert (x509.Certificate):
            The root CA certificate currently presented by the server.
        quick_check (bool, optional):
            If True, perform a fast lookup to confirm whether the host and root
            fingerprint match a previously approved record. Defaults to False.

    Returns:
        bool | tuple[ErrorLevel, Optional[str]]:
            - If `quick_check` is True:
                - `True` if the host/root pair matches an existing "approved" record.
                - `False` if no record exists or the fingerprints differ.
            - If `quick_check` is False:
                - `(ErrorLevel.CRIT, str)` if a mismatch is detected.
                - `(ErrorLevel.NONE, None)` if no issues or no record found.
    """
    logging.warning(f"-----------------------------------Entering prior_approval_check()--------------------------------------------------")
    # If refactor this function as a class, can persist the 'row' value below so there's only one SQL query
    host = flow.request.pretty_host
    if approved_hosts:
        logging.info(f'Approved hosts: {approved_hosts}')

    root_fingerprint = root_cert.fingerprint(hashes.SHA256()).hex()
    
    ############ Need to extend this to examine root cert parameters!!!!!!!!!!
    with sqlite3.connect(CONFIG.db_path) as conn:
        row = conn.execute("SELECT decision, root FROM decisions WHERE host = ?", (host,)).fetchone()               
        
        if quick_check == True:
            logging.info('Performing initial quick check...')
            if row and row[0] == "approved" and row[1] == root_fingerprint:
                logging.info(f"Root CA for {host} remains consistent with previously stored record in database; skipping further checks.")
                return True
            else:
                if not row:
                    logging.info(f"No record for {host} found in database; proceeding with further checks.")
                return False
        
        elif quick_check == False:  # Note - Should never get to this code path on subsequent function call if the earlier check above returned True.
            logging.info('Performing second-pass check for root cert drift in database.')
            if row and row[0] == "approved" and row[1] != root_fingerprint:
                logging.info(f"Root CA for {host} inconsistent with previously observed!")   
                violation = f"⚠️ Root CA for <b>{host}</b> inconsistent with previously observed!"
                return ErrorLevel.CRIT, violation
            logging.info(f"No mismatched root CA records found for {host} in database.")   
        return ErrorLevel.NONE, None   # Assumes no row returned, or consistent root_fingerprint 

def record_decision(host, decision, root_fingerprint) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(CONFIG.db_path) as conn:
        conn.execute("REPLACE INTO decisions (host, decision, root, timestamp) VALUES (?, ?, ?, ?)", (host, decision, root_fingerprint, now))
        conn.commit()
    #global approved_hosts
    #if decision == "approved":
        #approved_hosts.add(host)
        #logging.info(f'Approved hosts after adding from user decision: {approved_hosts}')

def sct_check(flow: http.HTTPFlow, root: x509.Certificate) -> Tuple[ErrorLevel, Optional[str]]:
    logging.warning(f"-----------------------------------Entering sct_check()--------------------------------------------------")
    cert   = flow.server_conn.certificate_list[0].to_cryptography()
    issuer_cert = flow.server_conn.certificate_list[1].to_cryptography()
    warnings = []
    violations = []
    logging.info(f'Input cert: {cert.subject.rfc4514_string()}')
    logging.debug(f'Issuer cert: {issuer_cert.subject.rfc4514_string()}')
    
    # Check for SCTs & extract data
    scts = verify_SCTs.extract_scts(cert, ct_log_map)
    if not scts:
        # TODO: Update code to account for external SCTs (e.g. delivered via OCSP or during TLS negotation).  Although these
        # alternative SCT delivery methods are exceedingly rare, this check should not result in FATAL errors until those methods are added.
        logging.error(f"Cert for {flow.request.pretty_url} missing SCT(s)!")
        violation = '⚠️ Certificate missing <a href=https://certificate.transparency.dev/howctworks/ target="_blank">Signed Certificate Timestamps</a> (SCTs)'
        return ErrorLevel.ERROR, violation
    
    # Print out SCT details for debugging purposes
    for i, sct in enumerate(scts, 1):
        logging.debug("\n")
        logging.debug(f"SCT #{i}")
        for k, v in sct.items():
            logging.debug(f"  {k}: {v}")
        if sct["extension_bytes"] != '':
            logging.warning('  SCT extensions found')
            sct_extension = bytes.fromhex(sct["extension_bytes"])
        
        # Validate SCT digital signatures (if enabled)
        if CONFIG.verify_signatures:
            validated, error, leaf_struct = verify_SCTs.validate_signature(cert, issuer_cert, sct)
            if error:
                logging.error(f"Error during SCT validation attempt for SCT #{i}: {error}")
                warnings.append(f'⚠️ Encountered error trying to validate SCT #{i}: {error}')
            elif not validated:
                logging.error(f"SCT signature #{i} FAILED to validate!")
                violations.append(f'⛔ Digital signature validation for <a href=https://certificate.transparency.dev/howctworks/ target="_blank">SCT</a> #{i} failed.')
            else:
                logging.info(f" SCT #{i} digital signature verified")

        # Cryptographically audit CT log inclusion (if enabled)
        if validated and CONFIG.verify_inclusion:
            included, error = verify_SCTs.verify_inclusion(leaf_struct, sct["ct_log_url"], sct["timestamp_unix"], sct["ct_log_mmd"])
            if included:
                logging.info(f" Inclusion in {sct["ct_log_description"]} verified")    
            else:
                warnings.append(f'⚠️ {error}')

    if violations:
        return ErrorLevel.FATAL, f'{"<br>".join(violations, warnings)}' 
    
    if warnings:
        return ErrorLevel.ERROR, f'{"<br>".join(warnings)}'

    return ErrorLevel.NONE, None

def ct_quick_check(flow: http.HTTPFlow, root: x509.Certificate) -> Tuple[ErrorLevel, Optional[str]]:
    """
    Make call to SSLMate to check for cert/precert inclusion in Certificate Transparency log(s) and cert revocation.
    LIMITATION: SSLMate purges expired certificates, so if cert is expired this check is bypassed.
    """
    logging.warning(f"-----------------------------------Entering sct_quick_check()--------------------------------------------------")

    if not CONFIG.quick_check:
        return ErrorLevel.NONE, None

    else:
        cert   = flow.server_conn.certificate_list[0].to_cryptography()
        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        
        if now > not_after:
            logging.info('Skipping SSLMate lookup since leaf certificate has expired.')
            return ErrorLevel.NONE, None

        violations = []
        found, revoked, error = verify_SCTs.ctlog_quick_check(flow, cert)

        if error:
            logging.error(f'Could not check SSLMate for Certificate Transparency inclusion: {error}.')
            return ErrorLevel.ERROR, f'{error}'

        if found:
            logging.info(f'Publication in Certificate Transparency log confirmed.')
        else:
            not_before = cert.not_valid_before_utc
            logging.info(f'Leaf cert not_valid_before date (UTC): {not_before}')
            
            if now - timedelta(hours=24) < not_before <= now:
                logging.info('Cert is within Maximum Merge Delay (MMD) window for publishing to Certificate Transparency log.')
                return ErrorLevel.INFO, f'<span style="color: blue;">&nbsp;🛈</span>&nbsp;&nbsp;Cert not found in CT logs, but within 24hr <a href=https://datatracker.ietf.org/doc/html/rfc6962#section-3 target="_blank">Maximum Merge Delay</a> period.'

            elif not_before > now:
                logging.info("Certificate is not valid yet (Not Before timestamp is in the future)!")
                violations.append(f'⛔ Certificate not yet valid! Issue date: {not_before} ')

            else:
                logging.info("Certificate has been valid for more than 24 hours and should be published in CT logs by now.")
            logging.warning('Leaf cert NOT FOUND in CT log!')
            violations.append('⛔ Certificate not logged in <a href=https://certificate.transparency.dev/howctworks/ target="_blank">Certificate Transparency</a> log')

        if not revoked:
            logging.info('Certificate not revoked.')
        elif revoked:
            logging.error(f"Leaf cert for '{flow.request.pretty_host}' REVOKED!\n                      Reason code: {revoked}")
            violations.append(f'⛔ Certificate marked as revoked at {revoked}')
        
        if violations:
            return ErrorLevel.FATAL, f'{"<br>".join(violations)}' 

        return ErrorLevel.NONE, None

def verify_cert_caa(flow: http.HTTPFlow, root: x509.Certificate) -> tuple[ErrorLevel, Optional[str]]:
    """ 
    For each FQDN in the cert, verify if the issuing CA is authorized via CAA.  Supports both 'issue' and 'issuewild' tags.  Returns a dictionary in the form of {domain: allowed}.

    Args:
        flow (mitmproxy.flow object): The flow for the current HTTP request; used to extract iussing CA and look up CAA domain identifiers.
        root (cryptography.x509.Certificate): Unused by verify_cert_caa(), but part of common for loop that calls into various CertGuard check functions.

    Returns:
        tuple[ErrorLevel, str]: A tuple consisting of the ErrorLevel (based on the verdict for the CAA verification logic) and, if applicable, a string 
        capturing the violation(s) encountered.
    """
    logging.warning(f"-----------------------------------Entering verify_cert_caa()---------------------------------------------")

    leaf = flow.server_conn.certificate_list[0]
    x509_leaf = leaf.to_cryptography()
    
    orgs=[]
    for attr in x509_leaf.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME):
        org = attr.value
        orgs.append(org)
        logging.info(f' Extracted Organization for Issuing CA Cert:  O="{org}"')
    if len(orgs) >= 2:
        logging.info(f' Multiple Orgs found in Issuing CA: {orgs}')
        return ErrorLevel.FATAL, f'⛔ Multiple Organization values encountered inside Issuing CA cert! <b>{",".join(orgs)}</b>' 
    
    ca_identifiers=ca_org_to_caa.get(org, ["UNKNOWN issue-domain-name identifier!  Please update 'ca_org_mapping.py' file"]) 
    logging.info(f' Matching CA identifiers: {ca_identifiers}')

    # Gets all FQDNs in cert (CN + SANs).  We won't check against all, but this lets us check for wildcard entries.
    cert_domains = get_cert_domains(x509_leaf)
    if len(cert_domains) == 0:
        logging.error(f'No FQDNs found in cert presented when connecting to {fqdn}.')
        return ErrorLevel.FATAL, f'Certificate returned for {fqdn} does not contain any FQDNs!' 
    logging.debug(f'All domains from leaf cert: {cert_domains}')
    
    check_domains=[]
    fqdn = (flow.request.pretty_host).lower()
    if fqdn in cert_domains:
        check_domains.append(fqdn)
        
    # Check to see if FQDN in URL is handled via wildcard entry in cert
    fqdn_parts=fqdn.split(".")
    if len(fqdn_parts) > 2:
        base_domain = ".".join(fqdn_parts[1:])
        logging.info(f' base_domain: {base_domain}')
        if f'*.{base_domain}' in cert_domains:
            check_domains.append(f'*.{base_domain}')

    if len(check_domains)==0:
        logging.error(f'Certificate not valid for FQDN of {fqdn}.')
        return ErrorLevel.CRIT, f'⚠️ Certificate <a href=https://knowledge.digicert.com/solution/name-mismatch-in-web-browser target="_blank">name mismatch</a>; cert not valid for <code>{fqdn}</code>.' 

    logging.info(f' Checking CAA records for these domains = {check_domains}')

    results = {}
    for domain in check_domains:
        results[domain], other_errors, records_found = check_caa_per_domain(domain, ca_identifiers)
    logging.info(f'Results from check_caa_per_domain(): {results}')

    caa_violations=[]
    return_violations=[]
    for domain, allowed in results.items():
        if not allowed:
            logging.critical(f'FQDN in cert not authorized by CAA record: {domain}')
            caa_violations.append(domain)

    if not records_found:
        return ErrorLevel.NONE, f'<span style="color: blue;">&nbsp;🛈</span>&nbsp;&nbsp;No published CAA records identified.'

    if caa_violations:
        return_violations.append(f'⚠️ FQDN(s) in cert not authorized by CAA record: <b>{",".join(caa_violations)}</b>')
    
    if other_errors:
        return_violations.append(f'⚠️ Critical condition(s) encountered during <a href=https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization target="_blank">CAA</a> verification:<br>    {other_errors}')

    if return_violations:
        return ErrorLevel.WARN, f'{"<br>".join(return_violations)}' 

    return ErrorLevel.NONE, None    

def check_caa_per_domain(domain: str, ca_identifiers: list[str]) -> tuple[bool, str | None, bool]:
    """
    Walks DNS tree per RFC8659, searching for CAA records and checking that specified issuer-domain-names match Issuing CA for leaf certificate.
    
    Args:
        domain:         FQDN of flow target host
        ca_identifiers: Pre-loaded mapping of issuer-domain-name values for popular Certification Authorities
    
    Returns:
        bool:           True to indicate that a matching CAA record was identified 
        str | None:     None for clean CAA matches, otherwise string with additional information
        records_found:  Boolean to indicate if any CAA records were found while climbing DNS tree
    """
    logging.warning(f"-----------------------------------Entering check_caa_per_domain()----------------------------------------")
    # Check CAA records for the given domain.
    is_wildcard = domain.startswith("*.")

    if is_wildcard:
        logging.info(f' Checking wildcard domain: {domain}')
    else:
        logging.info(f' Checking NON-wildcard domain: {domain}')
    
    labels = domain.lstrip("*.").split(".")     #  Strip wildcard prefix if present

    etld = False 
    records_found = False
    issue_properties = None
    issuewild_properties = None

    for i in range(len(labels)):  # Climb the DNS tree checking for applicable CAA record(s), warn if only found at TLD level.
        check_domain = ".".join(labels[i:])
        logging.warning(f' Checking for DNS CAA records published at {check_domain} against enumerated CA identifiers: {ca_identifiers}')
        
        # Check to see if comparing against an "effective TLD" / public suffix, with exceptions as defined in config.toml.
        # See https://developer.mozilla.org/en-US/docs/Glossary/eTLD and https://publicsuffix.org/ for reference
        if check_domain in CONFIG.public_suffix_list and not check_domain in CONFIG.exempt_eTLDs: etld = True 

        try:
            current_resolver = CONFIG.resolvers[0]
            logging.debug(f'   Using resolver: {current_resolver}')

            query = dns.message.make_query(check_domain, dns.rdatatype.CAA, want_dnssec=True)
            got_response=False
            while got_response==False:
                try:
                    answers = dns.query.udp_with_fallback(query, current_resolver, timeout=CONFIG.dns_timeout)  # timeout parameter is required, otherwise mitmproxy can freeze
                    got_response=True
                except dns.exception.Timeout:
                    CONFIG.resolvers.rotate(1)
                    current_resolver = CONFIG.resolvers[0]
                    logging.error(f'DNS query using resolver {CONFIG.resolvers[-1]} for "{check_domain}" timed out!!  ...Trying again with resolver {current_resolver}.')
                except Exception as e:
                    CONFIG.resolvers.rotate(1)
                    current_resolver = CONFIG.resolvers[0]
                    logging.debug(f"Exception encountered for DNS query using resolver {CONFIG.resolvers[-1]}: {e}")
                    logging.error(f'  --> Trying again with resolver {current_resolver}.')

            if answers[1]:
                logging.warning(f'DNS query had to fallback to TCP due to truncated response')
            
            answers=answers[0]
            logging.debug(f'Full resource record set: {answers}')
           
            if answers.flags & dns.flags.AD:   # Indicates a DNSSEC-validated resposne; dns.flags.AD = 32
                logging.info(f'DNSSEEC validation successful (AD bit set in response).')
            else:
                logging.warning(f'DNSSEEC validation for {check_domain} failed.')

        except Exception as e:
            logging.warning(f' Aborting further CAA checks due to exception: "{e}"')
            continue
        
        if answers.answer:
            for rrset in answers.answer:
                logging.info(f'Full resource record set:\n{rrset.to_text()}')

                issue_properties = []
                issuewild_properties = []

                for rdata in rrset:
                    if not isinstance(rdata, CAA.CAA):
                        logging.info(f' Skipping checks against malformed or non-CAA record: {rrset}')
                        continue
                    elif rdata.flags not in (0, 128):    # All other flags are reserved per RFC8659.
                        logging.error(f'Invalid CAA flag value ({rdata.flags}) encountered; full CAA record: {rdata.to_text()}')
                        continue
                    elif rdata.tag.decode('utf-8').lower() not in ("issue","issuewild","issuemail","issuevmc","iodef","contactemail","contactphone"):
                        logging.error(f'Invalid CAA tag value ("{rdata.tag.decode('utf-8')}") encountered; full CAA record: {rdata.to_text()}')
                        continue
                    else:
                        if rdata.tag.decode('utf-8') == 'issue':
                            issue_properties.append(rdata.value.lower().decode('utf-8'))
                        if rdata.tag.decode('utf-8') == 'issuewild':
                            issuewild_properties.append(rdata.value.lower().decode('utf-8'))
                
                logging.debug(f'Is wildcard? {is_wildcard}')
                logging.debug(f'issuewild_properties: {issuewild_properties}')
                logging.debug(f'issue_properties: {issue_properties}')
                if is_wildcard:
                    if issuewild_properties:
                        records_found = True
                        if len(issuewild_properties) == 1 and issuewild_properties[0] == ";":  # CAA records are additive, so need to ensure blank record is by itself.
                            return False, f'Wildcard certificate issuance explicitly prohibited for {domain}!', records_found
                        for ca in ca_identifiers:
                            for ca_entry in issuewild_properties:
                                if ca in ca_entry:    # Important to use 'in' since issue tags can have extension properties specified by Certification Authory.
                                    if etld:
                                        logging.error(f'Authorizing wildcard CAA record (<code>{ca}</code>) *only* found at .{check_domain} eTLD!')    
                                        return True, f"&emsp;&nbsp;&nbsp;&nbsp;Wildcard CAA record ({ca}) <u>only</u> found at <b>.{check_domain}</b> eTLD!", records_found
                                    logging.warning(f"SUCCESS: Wildcard CA from mapping ({ca}) matched CAA record published at {check_domain}.")
                                    return True, None, records_found
                    
                # Fallthrough -- Either we're testing a non-wildcard cert entry OR we're testing a wildcard cert but there's no 'issuewild' property.
                if not issue_properties:
                    logging.warning(f" No 'issue' CAA records found at {check_domain}.")
                    continue
                if len(issue_properties) == 1 and issue_properties[0] == ";":  # CAA records are additive, so need to ensure blank record is by itself.
                    return False, f'Empty issuer-domain-name value (";") encountered at {check_domain}; certificate issuance explicitly prohibited for {domain}!', records_found
                
                if issue_properties:
                    records_found = True
                    logging.debug(f"'issue' properties values from CAA records: {issue_properties}")
                    for ca in ca_identifiers:
                        logging.debug(f"Checking against mapped issuer-domain-name: {ca}")
                        for ca_entry in issue_properties:
                            if ca in ca_entry:    # Note: Important to use 'in' since issue tags can have extension properties specified by Certification Authory.
                                if etld:
                                    logging.error(f"Authorizing CAA record ({ca}) only found at .{check_domain} eTLD!")    
                                    return True, f'&emsp;&nbsp;&nbsp;&nbsp;Matching CAA record (<code>{ca}</code>) <em>only</em> found at <b>.{check_domain}</b> eTLD!', records_found
                                logging.warning(f"SUCCESS: CA from mapping ({ca}) matched CAA record published at {check_domain}.")
                                return True, None, records_found

        else:  # No answer rdata retrieved from CAA query
            logging.info(f'No published CAA record found at {check_domain}.')
            continue
    
    # Exhausted CAA record search for DNS tree.  If CAA records found, but no matches for Issuing CA of leaf certificate, return warning.
    if is_wildcard and issuewild_properties:
        logging.error(f"Published 'issuewild' CAA records do not authorize Issuing CA of wildcard leaf cert!")
        return False, f"&emsp;&nbsp;&nbsp;&nbsp;Wildcard CAA records do not authorize CA for wildcard site certificate.", records_found
    
    if issue_properties:
        logging.error(f"Published 'issue' CAA records do not authorize Issuing CA for leaf cert!")
        return False, f"&emsp;&nbsp;&nbsp;&nbsp;CAA records do not authorize CA for site certificate.", records_found

    # No CAA records found at all
    logging.warning(f'No published CAA record found; return true per RFC8659')
    return True, None, records_found # No CAA record founds; return true per RFC8659

def test_check(flow: http.HTTPFlow, root: x509.Certificate) -> Tuple[ErrorLevel, Optional[str]]:
    # Modified example rule from mitmproxy documentation
    logging.warning(f"-----------------------------------Entering test_check()---------------------------------------------")
    if "https://www.example.com/path" in flow.request.pretty_url:
        logging.info("Triggered test_check().")
        violation = f'<span style="color: green;">&nbsp🛈</span>&nbsp&nbspExample URL accessed: <b>{flow.request.pretty_url}</b>.'
        return ErrorLevel.INFO, violation
    return ErrorLevel.NONE, None

def dane_check(flow: http.HTTPFlow, root: x509.Certificate):
    """Check for DANE TLSA records and, if found, validate server certificate per RFC 6698"""
    logging.warning(f"-----------------------------------Entering dane_check()---------------------------------------------")
    logging.debug(f'dane_validator.dnssec_failure: {dane_validator.dnssec_failure}')
    logging.debug(f'dane_validator.dane_failure:   {dane_validator.dane_failure}')
    logging.debug(f'dane_validator.violation:      {dane_validator.violation}')

    if dane_validator.dnssec_failure == True or dane_validator.dane_failure == True:
        violation = dane_validator.violation
        return ErrorLevel.FATAL, f'{violation}'    
    
    return ErrorLevel.NONE, None
#====================================================================== Main ===================================================================

# Class to inject OCSP Stapling requests
ocsp_addon = OCSPStaplingConfig()
dane_validator = DANETLSAValidator()

addons = [ocsp_addon, dane_validator]

approved_hosts = set()
pending_requests = {}

# Load Certifi roots + any custom roots
root_store = get_root_store()

# Load Certificate Transparency, optionally passing in legacy CT log file.
if os.path.exists("./resources/legacy_log.json"):
    ct_log_map = verify_SCTs.load_ct_log_list(old_ct_log='./resources/legacy_log.json')
else:
    ct_log_map = verify_SCTs.load_ct_log_list()

if ct_log_map == None:
    logging.fatal('Can not load Certificate Transparency log_list.json file!  Please check DNS resolution and Internet connectivity.')

def request(flow: http.HTTPFlow) -> None:
    highest_error_level = ErrorLevel.NONE.value
    host = flow.request.pretty_host
    headers = flow.request.headers
    referer_header = headers.get("referer", None)
    accept_header = headers.get("accept", None)
    if accept_header:
        accept_header = accept_header.lower()

    # Check for stapled OCSP response.
    if flow.server_conn:
        conn_id = id(flow.server_conn)
        if conn_id in ocsp_addon.ocsp_by_connection:
            # Copy OCSP strings to flow metadata
            flow.metadata.update(ocsp_addon.ocsp_by_connection[conn_id])
            logging.debug(f"[OCSP] Attached OCSP data to flow for {flow.request.pretty_host}")
            
            # Retrieve any SCT extensions attached to stapled OCSP responses
            if ocsp_addon.ocsp_sct_list:
                if conn_id in ocsp_addon.ocsp_sct_list:
                    stapled_sct = ocsp_addon.ocsp_sct_list[conn_id]
                    logging.debug(f"SCT extension found in stapled OCSP response: {stapled_sct}")
                    del ocsp_addon.stapled_sct[conn_id]
                    
                    # Return during hunt for any website using stapled SCTs in OCSP response.
                    violation = f'Found SCT in stapled OCSP response for <b>{flow.request.pretty_url}</b>.'
                    return ErrorLevel.INFO, violation

                    # TODO: If ever encounter real-life SCT in stapled OCSP response, add code to pass into 
                    # verify_SCTs.py for signature validation & inclusion proofing.

            # Clean up temporary storage
            del ocsp_addon.ocsp_by_connection[conn_id]

    # Check to see if page is a navigation request that can be cleanly intercepted
    is_main_page = is_navigation_request(flow, referer_header, accept_header)
    logging.info(f'====> TLS version for server:    {flow.server_conn.tls_version}')
    logging.info(f'====> New navigation request:    {is_main_page}')
    logging.info(f'====> Request URL:               {flow.request.pretty_url}')
    logging.info(f'====> Method:                    {flow.request.method}')
    logging.info(f'====> Referer:                   {referer_header}')
    logging.info(f'====> Accept:                    {accept_header}')

    if host in approved_hosts:
        logging.info(f"Host '{host}' already accepted or validated during this CertGuard session... skipping further checks.")
        return

    cert_chain = flow.server_conn.certificate_list
    if not cert_chain:
        logging.info(f'Unencrypted connection; skipping further checks.')
        return
    
    leaf_cert = cert_chain[0]
    logging.debug(f'---> Leaf cert SubAltName(s):   {[name.value for name in leaf_cert.altnames]}')

    # Convert chain certs to cryptography.x509.Certificate objects
    cert_chain = [cert.to_cryptography() for cert in cert_chain]
    
    # Retrieve validated root cert as cryptography.hazmat.bindings._rust.x509.Certificate object.
    root_cert, claimed_root = get_root_cert(cert_chain, root_store)
    if root_cert:
        root_hash = (root_cert.fingerprint(hashes.SHA256())).hex()
    else:
        # Note: As currently constructed, this error cannot be anything less than FATAL since the 'Proceed Anyway' button won't work.
        logging.fatal(f'FATAL: Could not validate trust anchor root ({claimed_root}) for cert chain!')
        violation = f'⛔ Could not validate cert against claimed root of:<br>&emsp;&emsp;<b>{claimed_root}</b>'
        error_screen(flow, None, ErrorLevel.FATAL.color, [violation], ErrorLevel.FATAL.value)
        return
    
    # Check to see if site is already approved in the database.
    prior_approval = prior_approval_check(flow, root_cert, quick_check=True)
    if prior_approval:
        logging.info(f"User has previously approved {host}.")
        approved_hosts.add(host)  # In-memory cache for improvement performance
        return
    else:
        logging.info(f'Host {flow.request.pretty_host} not found to be previously approved; continuing checks.')

    # Detect approval token from client request
    if CONFIG.token_mode == "get":
        token = flow.request.query.get(BYPASS_PARAM)
        logging.info(f"Detected token in request:       {token}.")
    elif CONFIG.token_mode == "post":
        token = flow.request.urlencoded_form.get(BYPASS_PARAM)
        logging.info(f"Detected token in request:       {token}.")
    elif CONFIG.token_mode == "header":
        token = flow.request.headers.get(f"X-{BYPASS_PARAM}")
        logging.info(f"Detected token in request:       {token}.")

    if token and token in pending_requests:
        orig_req = pending_requests.pop(token)
        if CONFIG.token_mode == "header":
            if CONFIG.intercept_mode == "strict":                       
                # Best effort to replay original request; works for simple HTML form POST requests that return 302 or HTML.
                flow.request.method = orig_req["method"]
                flow.request.path = orig_req["path"]
                flow.request.headers.clear()
                flow.request.headers.update(orig_req["headers"])
                flow.request.content = orig_req["body"]
            else:
                # Synthetic response to close POST request; JavaScript handles page refresh.
                flow.response = http.Response.make(200, f"CertGuard: '{host}' added as approved host via token {token}.", {"Content-Type": "text/plain"})
        elif CONFIG.token_mode == "post":
            flow.request.method = orig_req["method"]
            flow.request.path = orig_req["path"]
            flow.request.content = orig_req["body"]
        elif CONFIG.token_mode == "get":
            # Remove CertGuard parameter before redirect.
            flow.request.query.pop(BYPASS_PARAM, None)
            flow.response = http.Response.make(302, b"", {"Location": flow.request.url})

        logging.warning(f"User has accepted warnings for {host} via token: {token}.  Decision will be persisted to database & cached for this session.")
        record_decision(host, "approved", root_hash)
        approved_hosts.add(host)
        return

    if CONFIG.intercept_mode == "compatible":
        if is_main_page:
            logging.info(f'Main page navigation; proceeding for further analysis...')
            pass
        else:
            logging.info(f'Not a main page navigation; skipping further checks.')
            return

    # Create a token for this blocked request
    token = str(uuid.uuid4())
    pending_requests[token] = {
        "method": flow.request.method,
        "path": flow.request.path,
        "headers": dict(flow.request.headers),
        "body": flow.request.content
    }

    my_checks = [
        dane_check,
        root_country_check, 
        controlled_CA_checks, 
        expiry_check, 
        revocation_checks, 
        identity_check, 
        prior_approval_check, 
        sct_check, 
        ct_quick_check,
        verify_cert_caa,
        test_check,
    ] 

    violations=[]
    for check in my_checks:
        error, violation = check(flow, root_cert)
        if error.value > highest_error_level:
            highest_error_level = error.value
            blockpage_color = error.color
        violations.append(violation)

    logging.info(f'-----------------------------------END verification for {host}--------------------------------------------')
    logging.warning(f"----> The highest_error_level value is: {highest_error_level}.")
    if highest_error_level > ErrorLevel.NONE.value:
        error_screen(flow, token, blockpage_color, violations, highest_error_level)
        record_decision(host, "blocked", root_hash)
        logging.error(f"Request to {host} blocked; Token={token}")
    else:
        # If all checks have passed for a main page navigation, for performance reasons treat domain as trusted for remainder of mitmproxy session.
        if is_main_page:
            logging.info(f'All checks passed for {host}; caching as approved host for this CertGuard session.')
            approved_hosts.add(host)
            logging.info(f'Approved hosts after adding in final block: {approved_hosts}')
            return
    