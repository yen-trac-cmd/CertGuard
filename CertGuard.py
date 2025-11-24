from certguard_checks import (
    dane_check,
    dnssec_check,
    root_country_check, 
    controlled_CA_checks, 
    expiry_check, 
    revocation_checks, 
    identity_check, 
    critical_ext_check, 
    prior_approval_check, 
    sct_check, 
    ct_quick_check, 
    caa_check, 
    x509_version_check,
    test_check
)
from certguard_checks import dane_validator
from certguard_config import BYPASS_PARAM, Config, DisplayLevel, ErrorLevel, Finding, Logger
from chain_builder import get_root_cert, normalize_chain
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import hashes
from error_screen import error_screen
from helper_functions import clean_error, get_cert_domains, get_root_store, is_navigation_request, record_decision, supported_ciphers_list
from mitmproxy import ctx, http, addonmanager
from tls_extensions import OCSPStaplingConfig
import json
import logging
import os
import sqlite3
import uuid

#================================================================ Main ================================================================

config = Config()                                       # Class to set various CertGuard configuration parameters
ocsp_addon = OCSPStaplingConfig()                       # Class to inject OCSP Stapling requests into TLS handshake to upstream servers
addons = [ocsp_addon]

log = Logger.get_logger()                               # Configure file logger
root_store = get_root_store(config.custom_roots_dir)    # Load Certifi roots + any custom roots

approved_hosts = set()
pending_requests = {}

#======================================================== mitmproxy event hooks ========================================================

def load(loader: addonmanager.Loader) -> None:
    """
    Sets mitmproxy console logging level, TLS parameters, and creates CertGuard database if not present.
    """
    if config.logging_level in ["debug", "info", "warn", "error", "alert"]:
        opts = ctx.options.keys()
        if "console_eventlog_verbosity" in opts:
            # Running in mitmproxy console UI
            logging.info("Detected mitmproxy console UI")
            ctx.options.console_eventlog_verbosity = config.logging_level
        else:
            # Running in mitmdump (or mitmweb)
            logging.info("Detected mitmdump/mitmweb")
            ctx.options.termlog_verbosity = config.logging_level
    else:
        logging.warning(f"Invalid console logging mode defined in config.toml; defaulting to 'info' level.")

    match config.min_tls_version:
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

    if config.ciphersuites != None:
        supported_ciphers = supported_ciphers_list()
        target_ciphers = []
        for cipher in config.ciphersuites.split(':'):
            if cipher in supported_ciphers:
                target_ciphers.append(cipher)
        ctx.options.ciphers_server = ":".join(target_ciphers)
        logging.debug(f'Configured ciphers: \n* {"\n* ".join(target_ciphers)}')

    # Disable native mitmproxy SSL/TLS checks, if configured, in favor of CertGuard's checks
    # Equivalent to starting mitmproxy with '--ssl-insecure' argument
    if config.certguard_checks:
        ctx.options.ssl_insecure = True

    # Create SQLite DB and table if not exists
    with sqlite3.connect(config.db_path) as conn:
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

def request(flow: http.HTTPFlow) -> None:
    findings:list[Finding]=[]
    highest_error_level = ErrorLevel.NONE.value
    host = flow.request.pretty_host
    headers = flow.request.headers
    referer_header = headers.get("referer", None)
    accept_header = headers.get("accept", None)
    if accept_header:
        accept_header = accept_header.lower()

    cert_chain = flow.server_conn.certificate_list
    if not cert_chain:
        logging.info(f'Unencrypted connection; skipping further checks.')
        return

    if host in approved_hosts:
        logging.info(f"Host '{host}' already accepted or validated during this CertGuard session... skipping further checks.")
        return

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
                    finding = f'Found SCT in stapled OCSP response for <b>{flow.request.pretty_url}!!</b>.'
                    findings.append(Finding(DisplayLevel.WARNING, finding))
                    #error_screen(config, flow, None, ErrorLevel.FATAL.color, [finding], ErrorLevel.FATAL.value)

                    # TODO: If ever encounter real-life SCT in stapled OCSP response, pass into Certificate Transparency 
                    # module ("ct") for signature validation & inclusion proofing.

            # Clean up temporary storage
            del ocsp_addon.ocsp_by_connection[conn_id]

    # Check to see if page is a navigation request that can be cleanly intercepted
    is_main_page = is_navigation_request(flow, referer_header, accept_header)
    logging.info(f'Connection ID:                   {flow.server_conn.id}')
    logging.info(f'====> Target host:               {flow.request.host}')
    logging.info(f'====> TLS version for server:    {flow.server_conn.tls_version}')
    logging.info(f'====> New navigation request:    {is_main_page}')
    logging.info(f'====> Request URL:               {flow.request.url}')
    logging.info(f'====> Method:                    {flow.request.method}')
    logging.info(f'====> Referer:                   {referer_header}')
    logging.info(f'====> Accept:                    {accept_header}')
    logging.debug(f'====> Leaf cert SubAltName(s):  {", ".join([name.value for name in cert_chain[0].altnames if type(name.value) == str])}')

    if flow.request.pretty_host != flow.request.host:
        logging.error(f"Mismatch between mitmproxy host ({flow.request.host}) and HTTP 'Host' header ({flow.request.pretty_host}).")

    # Convert certificate chain to a properly-ordered, de-duplicated list of cryptography.x509.Certificate objects  
    # This step is necessary to compensate for the (many!) misconfigured servers encountered on the Internet
    cert_chain, errors = normalize_chain([cert.to_cryptography() for cert in cert_chain])
    if errors:
        highest_error_level = ErrorLevel.ERROR.value
        findings.append(Finding(DisplayLevel.WARNING, errors))
    
    # Retrieve validated root cert as cryptography.hazmat.bindings._rust.x509.Certificate object.
    root_cert, claimed_root, verification_error, self_signed = get_root_cert(cert_chain, root_store)
    if root_cert:
        root_hash = root_cert.fingerprint(hashes.SHA256()).hex()
        # Add root cert to chain (if not already present) for a complete / validated chain
        if cert_chain[-1].subject == cert_chain[-1].issuer:
            highest_error_level = ErrorLevel.ERROR.value
            findings.append(Finding(DisplayLevel.WARNING, f'⚠️ Root certificate present in server-supplied cert chain.'))
        else:
            cert_chain.append(root_cert)
        
        # Fetch org name for verbose block pages        
        for attr in root_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME):
            ca_org = attr.value
        findings.append(Finding(DisplayLevel.VERBOSE, f'<span style="color: blue;">&nbsp;🛈</span>&nbsp;&nbsp;Root CA Operator: {ca_org}'))

    elif self_signed:
        #TODO: Add logic for DANE usage type 3, where cert may be self-attested in TLSA record.
        findings.append(Finding(DisplayLevel.WARNING, f'⚠️ Encountered self-signed certificate:<br>&emsp;&emsp;<b>{self_signed.subject.rfc4514_string()}</b>'))
        highest_error_level = ErrorLevel.ERROR.value
        blockpage_color = ErrorLevel.ERROR.color
        root_hash = self_signed.fingerprint(hashes.SHA256()).hex()
    elif claimed_root:
        #TODO: Add logic for DANE usage type 2, where root may be a private CA.
        logging.error(f'Could not validate cert against claimed Issuer cert of: ({claimed_root}).')
        findings.append(Finding(DisplayLevel.CRITICAL, f'⛔ Could not validate cert against claimed Issuer cert of:<br>&emsp;&emsp;<b>{claimed_root}</b>'))
        if len(cert_chain) == 1:
            logging.error(f'Server failed to send complete certificate chain.')
            findings.append(Finding(DisplayLevel.WARNING, '&emsp;&emsp;▶ Server failed to send complete certificate chain.'))
        highest_error_level = ErrorLevel.FATAL.value
        blockpage_color = ErrorLevel.FATAL.color
        root_hash = f"Unidentified_root - {claimed_root}"

    if verification_error:
        logging.error(f'Encountered verification error while building certificate chain: {verification_error}')
        findings.append(Finding(DisplayLevel.CRITICAL, f'⛔ Could not verify certificate chain: {verification_error}'))
        highest_error_level = ErrorLevel.FATAL.value
        blockpage_color = ErrorLevel.FATAL.color
        root_hash = "Unverified root"

    # Check to see if site is already approved in the database.
    prior_approval = prior_approval_check(flow, cert_chain, quick_check=True)
    if prior_approval:
        logging.info(f"User has previously approved {host}.")
        approved_hosts.add(host)  # In-memory cache for improved performance
        return
    else:
        logging.info(f'Host {flow.request.pretty_host} not found to be previously approved; continuing checks.')

    # Detect approval token from client request
    if config.token_mode == "get":
        token = flow.request.query.get(BYPASS_PARAM)
        logging.info(f"Detected token in request:       {token}.")
    elif config.token_mode == "post":
        token = flow.request.urlencoded_form.get(BYPASS_PARAM)
        logging.info(f"Detected token in request:       {token}.")
    elif config.token_mode == "header":
        token = flow.request.headers.get(f"X-{BYPASS_PARAM}")
        logging.info(f"Detected token in request:       {token}.")

    if token and token in pending_requests:
        orig_req = pending_requests.pop(token)
        if config.token_mode == "header":
            if config.intercept_mode == "strict":                       
                # Best effort to replay original request; works for simple HTML form POST requests that return 302 or HTML.
                flow.request.method = orig_req["method"]
                flow.request.path = orig_req["path"]
                flow.request.headers.clear()
                flow.request.headers.update(orig_req["headers"])
                flow.request.content = orig_req["body"]
            else:
                # Synthetic response to close POST request; JavaScript handles page refresh.
                flow.response = http.Response.make(200, f"CertGuard: '{host}' added as approved host via token {token}.", {"Content-Type": "text/plain"})
        elif config.token_mode == "post":
            flow.request.method = orig_req["method"]
            flow.request.path = orig_req["path"]
            flow.request.content = orig_req["body"]
        elif config.token_mode == "get":
            # Remove CertGuard parameter before redirect.
            flow.request.query.pop(BYPASS_PARAM, None)
            flow.response = http.Response.make(302, b"", {"Location": flow.request.url})

        logging.warning(f"User has accepted warnings for {host} via token: {token}.  Decision will be persisted to database & cached for this session.")
        record_decision(config.db_path, host, "approved", root_hash)
        approved_hosts.add(host)
        return

    if config.intercept_mode == "compatible":
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
        root_country_check,     # Optional for mass scanning
        controlled_CA_checks,   # Optional for mass scanning
        expiry_check, 
        revocation_checks, 
        identity_check, 
        critical_ext_check,
        prior_approval_check,   # Optional for mass scanning
        sct_check, 
        #ct_quick_check,         # Can use this or the sct_check() and revocation_checks() for more thorough (albeit slower) validation.
        caa_check,
        test_check,
        x509_version_check,
        dnssec_check,
    ] 

    for check in my_checks:
        error, finding = check(flow, cert_chain)
        if error.value > highest_error_level:
            highest_error_level = error.value
            blockpage_color = error.color
        if finding:    
            findings.append(finding)
    
    findings.sort(key=lambda f: f.level)
    filtered_findings = [f.message for f in findings if f.level <= config.bp_verbosity]

    logging.info(f'-----------------------------------END verification for {host}--------------------------------------------')
    
    cleaned_errors = [clean_error(f) for f in filtered_findings]
    flow.metadata["CertGuard_findings"] = cleaned_errors if cleaned_errors else None
    flow.metadata["Highest_Errorlevel"] = highest_error_level
    if is_main_page:
        flow.metadata["Is_Main_Page"] = True

    logging.warning(f"----> The highest_error_level value is: {highest_error_level}.")
    if highest_error_level > ErrorLevel.NONE.value:
        error_screen(config, flow, token, blockpage_color, filtered_findings, highest_error_level)
        record_decision(config.db_path, host, "blocked", root_hash)
        logging.error(f"Request to {host} blocked; Token={token}")
    else:
        # If all checks have passed for a main page navigation, for performance reasons treat domain as cleared for remainder of mitmproxy session.
        logging.info(f'All checks passed for {host}; caching as cleared host for this CertGuard session.')
        approved_hosts.add(host)
        record_decision(config.db_path, host, "allowed", root_hash)
        #logging.info(f'Approved & cleared hosts after adding in final block: {approved_hosts}')

def response(flow: http.HTTPFlow) -> None:
    if flow.metadata.get("Is_Main_Page"):
        highest_error_level = flow.metadata.get("Highest_Errorlevel", 0)
        findings = flow.metadata.get("CertGuard_findings")

        log_entry = {
            "Response Code": flow.response.status_code, 
            "FQDN": flow.request.pretty_host, 
            "ErrorLevel": highest_error_level, 
            "Findings": findings
        }
        
        json_string = json.dumps(log_entry)
        # Strip outter JSON brackets before passing to logger
        json_fragment = json_string[1:-1]

        log.info(json_fragment)

def done() -> None:
    log_file = Logger.log_file
    dane_validator.done()
    
    try:
        with open(log_file, 'r+b') as f:
            f.seek(-2, os.SEEK_END)
            f.truncate()
            f.seek(0, os.SEEK_END)
            f.write(b'\n],')
            #dane_stats = (f'\n"DANE TLSA Validator statistics": {{"Validated": {dane_validator.stats['validated']}, "Failed": {dane_validator.stats['dane_failed']}, "No TLSA": {dane_validator.stats['no_tlsa']}, "DNS Failed": {dane_validator.stats['dns_failed']}, "DNSSEC Failed": {dane_validator.stats['dnssec_failed']}}}')
            #f.write(dane_stats.encode('utf-8'))
            f.write(b'\n}')
    except Exception as e:
        print(f'Error {e}')