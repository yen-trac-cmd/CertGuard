import json
import logging
import os
import re
import sqlite3
import uuid
from requests import get
from checks.certguard_checks import dane_validator
from checks.chain_builder import get_root_cert, normalize_chain, build_cert_index
from checks.helper_functions import cache_cert, clean_error, get_cert_stores, is_navigation_request, record_decision, supported_ciphers_list
from checks.tls_logic import OCSPStaplingConfig
from config.certguard_config import BYPASS_PARAM, Config, DisplayLevel, ErrorLevel, Finding, Logger
from cryptography.x509 import Certificate, NameOID
from cryptography.hazmat.primitives import hashes
from error_screen import error_screen
from utils.misc import func_name
from utils.x509 import fetch_issuer_certificate, get_akid, get_skid
from mitmproxy import ctx, http, addonmanager
from checks.certguard_checks import (
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

#================================================================ Main ================================================================

config = Config()                                               # Class to set various CertGuard configuration parameters
ocsp_addon = OCSPStaplingConfig()                               # Class to inject OCSP Stapling requests into TLS handshake to upstream servers
addons = [ocsp_addon]

log = Logger.get_logger()                                       # Configure file logger

# Load Certifi roots + any custom root, intermediate CA, or deprecated root CA certs 
root_store, deprecated_store, int_store, cache_store = get_cert_stores(config.custom_roots_dir, config.deprecated_dir, config.custom_ints_dir, config.cached_dir)

# Combine trusted roots and deprecated roots for verifying digital signatures when building certificate chains.
# Note that if a given certificate chains up to a deprecated (but otherwise still valid) root cert, a warning will be raised.
root_store.extend(deprecated_store)

# Build lookup dictionaries for parent cert discovery by AIA or subject
roots_by_subject, roots_by_ski = build_cert_index(root_store)
ints_by_subject,  ints_by_ski  = build_cert_index(int_store)

cache_by_ski: dict[str,Certificate]
cache_by_subject, cache_by_ski = build_cert_index(cache_store)

# List of deprecated CA cert hashes for cross-reference during chain building.
deprecated_roots: list[Certificate]  = [cert.fingerprint(hashes.SHA256()) for cert in deprecated_store]

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
                root_hash TEXT,
                subject TEXT,
                expiry TEXT,
                tag TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()

    logging.warning(f"===> Reloaded CertGuard Addon")

def request(flow: http.HTTPFlow) -> None:
    """CertGuard Hook for mitmproxy request()"""
    logging.info('═══════════════════════════════════ BEGIN New HTTP Request ═════════════════════════════════════════════════════════')
    findings:list[Finding]=[]
    highest_error_level = ErrorLevel.NONE.value
    blockpage_color = ErrorLevel.NONE.color
    host = flow.request.pretty_host
    headers = flow.request.headers
    referer_header = headers.get("referer", None)
    accept_header = headers.get("accept", None)
    if accept_header:
        accept_header = accept_header.lower()

    mitm_cert_chain = flow.server_conn.certificate_list
    if not mitm_cert_chain:
        logging.info(f'Unencrypted connection (or TLS handshake failed); skipping further checks.')
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
            logging.debug(f"Attached stapled OCSP data to flow metadata for {flow.request.pretty_host}")
            findings.append(Finding(DisplayLevel.VERBOSE, func_name(), ErrorLevel.NONE, f'<span style="color: blue;">&nbsp;🛈</span>&nbsp;&nbsp;Stapled OCSP report included in TLS negotiation.', 10100))
            
            # Retrieve any SCT extensions attached to stapled OCSP responses
            if ocsp_addon.ocsp_sct_list:
                if conn_id in ocsp_addon.ocsp_sct_list:
                    stapled_sct = ocsp_addon.ocsp_sct_list[conn_id]
                    logging.debug(f"SCT extension found in stapled OCSP response: {stapled_sct}")
                    del ocsp_addon.ocsp_sct_list[conn_id]
                    
                    # Raise immediate level-6 blockpage during hunt for *any* website adding SCTs as OCSP extension inside stapled responses.
                    finding = f'🎉 Found SCT in stapled OCSP response for <b>{flow.request.pretty_url}</b>!!'
                    highest_error_level = ErrorLevel.FATAL.value
                    findings.append(Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.FATAL, finding, 10101))
                    error_screen(config, flow, None, ErrorLevel.FATAL.color, [finding], ErrorLevel.FATAL.value)

                    # TODO: If ever encounter real-life SCT in stapled OCSP response, pass into ct_logic module
                    # for signature validation & inclusion proofing.

            # Clean up temporary storage
            del ocsp_addon.ocsp_by_connection[conn_id]

    # Check to see if page is a navigation request that can be cleanly intercepted
    is_main_page = is_navigation_request(flow, referer_header, accept_header)
    logging.info(f'Connection ID:                   {flow.server_conn.id}')
    logging.info(f'====> Target host:               {flow.request.host}')
    logging.info(f'====> IP Address + port:         {flow.server_conn.peername[0]}:{flow.server_conn.peername[1]}')
    logging.info(f'====> TLS version for server:    {flow.server_conn.tls_version}')
    logging.info(f'====> New navigation request:    {is_main_page}')
    logging.info(f'====> Request URL:               {flow.request.url}')
    logging.info(f'====> Method:                    {flow.request.method}')
    logging.info(f'====> Referer:                   {referer_header}')
    logging.info(f'====> Accept:                    {accept_header}')
    logging.debug(f'====> Leaf cert SubAltName(s):  {", ".join([name.value for name in mitm_cert_chain[0].altnames if type(name.value) == str])}')

    if flow.request.pretty_host != flow.request.host:
        logging.error(f"Mismatch between mitmproxy host ({flow.request.host}) and HTTP 'Host' header ({flow.request.pretty_host}).")

    # Convert certificate chain to a properly-ordered, de-duplicated list of cryptography.x509.Certificate objects  
    # This step is necessary to compensate for the (many!) misconfigured servers encountered on the Internet
    cert_chain: list[Certificate]
    cert_chain, errors = normalize_chain([cert.to_cryptography() for cert in mitm_cert_chain])
    if errors:
        highest_error_level = ErrorLevel.ERROR.value
        findings.append(Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.ERROR, errors, 10102))
    
    # Iterate through the server-provided chain to find the earliest trust anchor.
    # This allows us to ignore trailing cross-signed legacy certificates.
    root = None
    root_hash = None
    root_subject = None
    root_expiry = None
    
    root_already_present = False
    fetched_certs = []
    trust_found = False

    for i, cert in enumerate(cert_chain):
        cert_aki = get_akid(cert)
        
        # Check if cert is issued by a trusted root.
        if cert_aki in roots_by_ski:
            root = roots_by_ski[cert_aki]
            trust_found = True
        elif cert.issuer in roots_by_subject:
            root = roots_by_subject[cert.issuer]
            trust_found = True

        if trust_found:
            # Trim the chain to remove any unnecessary legacy certs provided after this one.
            cert_chain = cert_chain[:i+1]
            logging.info(f'Shortest path found! Trusted root identified via cert index {i}.')
            break

    # Perform AIA chasing if we couldn't find a matching root in the existing chain, or chain is incomplete.
    if not trust_found:
        top_of_chain = cert_chain[-1]

        if top_of_chain.subject == top_of_chain.issuer:
            root_already_present = True
            root = top_of_chain
            highest_error_level = ErrorLevel.ERROR.value
            findings.append(Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.ERROR, f'⚠️ Root certificate included in server-supplied cert chain.', 10103))
        else:
            while True:
                cert_aki = get_akid(top_of_chain)
                
                # Check trusted intermediate certificates
                if cert_aki in ints_by_ski:
                    intCA = ints_by_ski[cert_aki]
                    fetched_certs.append(intCA)
                    top_of_chain = intCA
                    logging.debug(f'Identified stored trusted intermediate CA ({intCA.subject.rfc4514_string()}) via dictionary lookup against AKI.')
                    continue
                elif top_of_chain.issuer in ints_by_subject:
                    intCA = ints_by_subject[top_of_chain.issuer]
                    fetched_certs.append(intCA)
                    top_of_chain = intCA
                    logging.debug(f'Identified stored intermediate CA ({intCA.subject.rfc4514_string()}) via dictionary lookup against Issuer subject.')
                    continue
                
                # Check trusted root certificates
                elif cert_aki in roots_by_ski:
                    root = roots_by_ski[cert_aki]
                    logging.debug('Identified trusted root via dictionary lookup against AKI.')
                    break
                elif top_of_chain.issuer in roots_by_subject:
                    root = roots_by_subject[top_of_chain.issuer]
                    logging.info('Identified trusted root via dictionary lookup against Issuer subject.')
                    break
                
                # Check cached certificates
                elif cert_aki in cache_by_ski:
                    cached_cert = cache_by_ski[cert_aki]
                    if cached_cert.subject == cached_cert.issuer:
                        logging.info(f'Identified cacheduntrusted root as: {cached_cert.subject.rfc4514_string()}')
                        root = cached_cert
                        break
                    else:
                        top_of_chain = cached_cert
                        fetched_certs.append(cached_cert)
                        logging.debug(f'Identified cached intermediate CA ({cached_cert.subject.rfc4514_string()}) via dictionary lookup against AKI.')
                        continue
                elif top_of_chain.issuer in cache_by_subject:
                    cached_cert = cache_by_subject[top_of_chain.issuer]
                    if cached_cert.subject == cached_cert.issuer:
                        logging.info(f'Identified cacheduntrusted root as: {cached_cert.subject.rfc4514_string()}')
                        root = cached_cert
                        break
                    else:
                        top_of_chain = cached_cert
                        fetched_certs.append(cached_cert)
                        logging.debug(f'Identified cached intermediate CA ({cached_cert.subject.rfc4514_string()}) via dictionary lookup against Issuer subject.')
                        continue

                # Attempt to fetch next cert in chain by chasing AIA
                chain_issuer = fetch_issuer_certificate(top_of_chain, fetched_certs)
                if not chain_issuer:
                    break
                else:
                    # Cache fetched certificates in memory, and also to filesystem for future sessions.
                    chain_issuer_ski = get_skid(chain_issuer)
                    cache_by_ski[chain_issuer_ski]=chain_issuer
                    cache_cert(chain_issuer, chain_issuer_ski.hex(), config.cached_dir)
                
                if chain_issuer.subject == chain_issuer.issuer:
                    logging.info(f'Identified untrusted root as: {chain_issuer.subject.rfc4514_string()}')
                    root = chain_issuer
                    break
                else:   # Fetched cert is an intermediate.
                    logging.warning(f'Fetched cert missing from chain: {chain_issuer.subject.rfc4514_string()}')
                    fetched_certs.append(chain_issuer)
                    top_of_chain = chain_issuer

    if fetched_certs:
        findings.append(Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.ERROR, f'⚠️ Server failed to send complete certificate chain.', 10104))
        cert_chain.extend(fetched_certs)

    # Verify full certificate chain and retrieve validated root cert.
    root_cert, claimed_root, verification_error, self_signed, tag = get_root_cert(cert_chain, root, roots_by_ski, deprecated_roots)

    if root_cert:
        root_cn = root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        root_desc = root_cn[0].value if root_cn else root_cert.subject.rfc4514_string()
        root_hash = root_cert.fingerprint(hashes.SHA256()).hex()
        root_subject = root_cert.subject.rfc4514_string()
        root_expiry = root_cert.not_valid_after_utc
        
        # Add root cert to chain (if not already present) for a complete / validated chain
        if not root_already_present:
            cert_chain.append(root_cert)
        
        # Check for Deprecated root
        if tag == "DEPRECATED":
            findings.append(Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.ERROR, f'⚠️ Root certificate (<code>{root_desc}</code>) is deprecated!', 10105))
            blockpage_color = ErrorLevel.ERROR.color
        elif tag == "UNTRUSTED":
            findings.append(Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.FATAL, f'⛔ Root certificate (<code>{root_desc}</code>) is Untrusted!', 10106))
            blockpage_color = ErrorLevel.FATAL.color
        
        # Fetch org name for verbose block pages        
        ca_org = None
        for attr in root_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME):
            ca_org = attr.value
        if not ca_org:
            violation = f"⛔ No Organization (O=) value found in root CA certificate:<br>&emsp;&emsp;▶ <b>{root_desc}</b>"
            findings.append(Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.CRIT, violation, 10107))
        else:
            findings.append(Finding(DisplayLevel.VERBOSE, func_name(), ErrorLevel.NONE, f'<span style="color: blue;">&nbsp;🛈</span>&nbsp;&nbsp;Root CA Operator: {ca_org}', 10108))

    elif self_signed:
        #TODO: Add logic for DANE usage type 3, where cert may be self-attested in TLSA record.
        findings.append(Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.ERROR, f'⚠️ Encountered self-signed certificate:&emsp;&emsp;<b>{self_signed.subject.rfc4514_string()}</b>', 10109))
        highest_error_level = ErrorLevel.ERROR.value
        blockpage_color = ErrorLevel.ERROR.color
        root_hash = self_signed.fingerprint(hashes.SHA256()).hex()
        root_subject = self_signed.subject.rfc4514_string()
        root_expiry = self_signed.not_valid_after_utc
    
    elif claimed_root:
        #TODO: Add logic for DANE usage type 2, where root may be a private CA.
        #logging.error(f'Could not validate chained cert against claimed Issuer of: {claimed_root}.')
        if tag == "INVALID":
            findings.append(Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL, f'⛔ Signature on {top_of_chain.subject.rfc4514_string()} failed to verify against claimed root of:<br>&emsp;&emsp;<b>{claimed_root}</b>', 10110))
        if tag == "ERROR":
            findings.append(Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL, f'⛔ Error ecountered attempting to validate cert against claimed Issuer cert of:<br>&emsp;&emsp;<b>{claimed_root}</b>', 10111))
        if len(cert_chain) == 1:
            logging.error(f'Server failed to send complete certificate chain.')
            findings.append(Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.ERROR, '&emsp;&emsp;▶ Server failed to send complete certificate chain.', 10112))
        highest_error_level = ErrorLevel.FATAL.value
        blockpage_color = ErrorLevel.FATAL.color
        root_hash = cert_chain[-1].fingerprint(hashes.SHA256()).hex()
        root_subject = claimed_root
        root_expiry = cert_chain[-1].not_valid_after_utc

    if verification_error:
        logging.error(f'Encountered verification error while building certificate chain: {verification_error}')
        findings.append(Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL, f'⛔ Could not verify certificate chain: {verification_error}', 10113))
        highest_error_level = ErrorLevel.FATAL.value
        blockpage_color = ErrorLevel.FATAL.color
        if not root_hash:
            root_hash = cert_chain[-1].fingerprint(hashes.SHA256()).hex()
        if not root_subject:
            root_subject = cert_chain[-1].subject.rfc4514_string()
        if not root_expiry:
             root_expiry = cert_chain[-1].not_valid_after_utc

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
        record_decision(config.db_path, host, "approved", root_hash, root_subject, root_expiry, tag)
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
        #controlled_CA_checks,   # Optional for mass scanning
        expiry_check, 
        revocation_checks, 
        identity_check, 
        critical_ext_check,
        #prior_approval_check,   # Optional for mass scanning
        sct_check, 
        #ct_quick_check,         # Can use this or the sct_check() and revocation_checks() for more thorough (albeit slower) validation.
        caa_check,
        test_check,
        x509_version_check,
        dnssec_check,
    ] 

    for finding in findings:
        if finding.error_level.value > highest_error_level:
            highest_error_level = finding.error_level.value

    for check in my_checks:
        finding: Finding = check(flow, cert_chain)
        if finding.error_level.value > highest_error_level:
            highest_error_level = finding.error_level.value
            blockpage_color = finding.error_level.color
        if finding.message:
            findings.append(finding)
    
    logging.info(f'-----------------------------------END verification for {host}--------------------------------------------')

    # Sort findings by display level and structure as JSON for the logfile.
    findings.sort(key=lambda f: f.display_level)
    filtered_findings = [f for f in findings if f.display_level <= config.bp_verbosity]
    cleaned_errors = [ {"finding_id": f.finding_id, "check": f.check, "error_level": f.error_level.value, "message": clean_error(f.message)} for f in filtered_findings ]
    flow.metadata["CertGuard_findings"] = cleaned_errors if cleaned_errors else None
    flow.metadata["Highest_Errorlevel"] = highest_error_level
    if is_main_page:
        flow.metadata["Is_Main_Page"] = True

    logging.warning(f"----> The highest_error_level value is: {highest_error_level}.")
    if highest_error_level > ErrorLevel.NONE.value:
        display_messages = [f.message for f in filtered_findings]
        error_screen(config, flow, token, blockpage_color, display_messages, highest_error_level)
        record_decision(config.db_path, host, "blocked", root_hash, root_subject, root_expiry, tag)
        logging.error(f"Request to {host} blocked; Token={token}")
    else:
        # If all checks have passed for a main page navigation, for performance reasons treat domain as cleared for remainder of mitmproxy session.
        logging.info(f'All checks passed for {host}; caching as cleared host for this CertGuard session.')
        approved_hosts.add(host)
        record_decision(config.db_path, host, "allowed", root_hash, root_subject, root_expiry, tag)

def response(flow: http.HTTPFlow) -> None:
    if flow.metadata.get("Is_Main_Page"):
        highest_error_level = flow.metadata.get("Highest_Errorlevel", 0)
        findings = flow.metadata.get("CertGuard_findings")

        log_entry = {
            "Response Code": flow.response.status_code, 
            "FQDN": flow.request.pretty_host, 
            "IP": flow.server_conn.peername[0],
            "Port": flow.server_conn.peername[1],
            "TLS_version": flow.server_conn.tls_version,
            "ErrorLevel": highest_error_level, 
            "Findings": findings
        }
        
        json_string = json.dumps(log_entry)
        # Strip outter JSON brackets before passing to logger
        json_fragment = json_string[1:-1]

        log.info(json_fragment)

def error(flow: http.HTTPFlow) -> None:
    logging.warning(f"-----------------------------------Entering error()-----------------------------------------------")
    highest_error_level = flow.metadata.get("Highest_Errorlevel", 0)
    findings = flow.metadata.get("CertGuard_findings")

    if flow.server_conn.tls_version is None:
        response_code = 635
        highest_error_level = -1
        findings = [{"finding_id": 39800, "check": "mitmproxy_tls_connection", "error_level": -1, "message": "Unable to establish TLS connection with server"}]
    else:
        response_code = 630

    log_entry = {
        "Response Code": response_code, 
        "FQDN": flow.request.pretty_host, 
        "IP": flow.server_conn.peername[0],
        "Port": flow.server_conn.peername[1],
        "TLS_version": flow.server_conn.tls_version,
        "ErrorLevel": highest_error_level, 
        "Findings": findings
    }
    
    json_string = json.dumps(log_entry)
    # Strip outter JSON brackets before passing to logger
    json_fragment = json_string[1:-1]

    log.info(json_fragment)

def http_connect_error(flow: http.HTTPFlow) -> None:
    logging.warning(f"-----------------------------------Entering http_connect_error()----------------------------------")
    
    #remote_host = flow.server_conn.address[0] if flow.server_conn.address else "Unknown"
    logging.error(f"Failed to connect to: {flow.server_conn.address[0]}")
    
    if flow.error:
        error_text = flow.error.msg
        # Regex to find standard IPv4 addresses in the error string
        # It matches sequences like '72.21.210.29'
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        failed_ips = re.findall(ip_pattern, error_text)
        
        if failed_ips:
            logging.error(f"Failed to connect to host using IPs: {', '.join(failed_ips)}")
            logged_ip = failed_ips[0]
        else:
            # Fallback to the intended address if parsing fails
            planned_address = flow.server_conn.address if flow.server_conn else "Unknown"
            logging.error(f"Connection failed to: {planned_address}. Error: {error_text}")
            logged_ip = "0.0.0.2"
    
    elif flow.server_conn and flow.server_conn.address:
        #logging.error(f"Failed to connect to: {flow.server_conn.address}")
        logged_ip = "0.0.0.0"
    else:
        # Catch-all
        logged_ip = "0.0.0.1"

    highest_error_level = -2
    findings = [{"finding_id": 39900, "check": "mitmproxy_tls_connection", "error_level": -1, "message": "Unable to establish server connection"}]
    
    log_entry = {
        "Response Code": 645, 
        "FQDN": flow.request.pretty_host, 
        "IP": logged_ip,
        "Port": flow.server_conn.address[1],
        "TLS_version": flow.server_conn.tls_version,
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
            f.write(b'\n]')
            #dane_stats = (f'\n"DANE TLSA Validator statistics": {{"Validated": {dane_validator.stats['validated']}, "Failed": {dane_validator.stats['dane_failed']}, "No TLSA": {dane_validator.stats['no_tlsa']}, "DNS Failed": {dane_validator.stats['dns_failed']}, "DNSSEC Failed": {dane_validator.stats['dnssec_failed']}}}')
            #f.write(dane_stats.encode('utf-8'))
            f.write(b'\n}\n')
    except Exception as e:
        print(f'Error {e}')