import logging
import sqlite3
from checks.caa_record_checker import check_caa_per_domain
from checks.ct_logic import ctlog_quick_check, extract_scts, load_log_list, validate_sct_signature, verify_inclusion
from checks.revocation_logic import check_cert_chain_revocation
from config.ca_org_mapping import ca_org_to_caa, ca_org_to_country
from config.certguard_config import Config, DisplayLevel, ErrorLevel, Finding
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from checks.dane_logic import DANETLSAValidator
from datetime import datetime, timedelta, timezone
from mitmproxy import http
from typing import Optional, Tuple
from utils.misc import func_name
from utils.x509 import get_cert_domains


config = Config()
dane_validator = DANETLSAValidator()

# Load Certificate Transparency log list, optionally passing in legacy CT log file.
ct_log_map = load_log_list("./resources/legacy_log.json")

def root_country_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    """
    Check the country declared in a root CA certificate's subject to see if it's blocked or allowed (depending on user configuration).

    Args:
        flow:       The mitmproxy.http.HTTPFlow object representing a single HTTP transaction.
        cert_chain: The complete, validated certificate chain for the current TLS connection.

    Returns:
        Tuple[ErrorLevel, Optional[str]]: 
            ErrorLevel: Enum indicating severity of check results.
            Optional[str]: Description of country violation, or None if not applicable.
    """
    logging.warning(f"-----------------------------------Entering root_country_check()----------------------------------")
    
    # Check for self-signed certs; no point in checking Country or Org in this case
    if len(cert_chain) == 1:
        # Skip for self-signed
        if cert_chain[0].subject == cert_chain[0].issuer:
            logging.warning('Skipping root_country_check() for self-signed certificate.')
            return ErrorLevel.NONE, None
        else:    # Best-effort attempt to identify country from issuing CA
            logging.warning('Unchained certificate; attempting best-effort country enumeration from Issuing CA cert.')
            ca_type = "Issuing"
            ca_cert = cert_chain[0].issuer
    else:
        if cert_chain[-1].subject != cert_chain[-1].issuer:
            logging.warning('Could not identify trusted root CA; best-effort attempt to identify country from Intermediate CA cert.')
            ca_type = "Intermediate"
        else:
            ca_type = "Root"
        ca_cert = cert_chain[-1].subject
    
    logging.info(f'{ca_type} certificate subject:       {ca_cert.rfc4514_string()}')

    # Extract country value from CA cert
    ca_country = ca_cert.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    if len(ca_country) == 1:
        ca_country = ca_country[0].value
    
    elif len(ca_country) == 0:
        org = ca_cert.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        #logging.warning(f'org = {org},  type = {type(org)}, length = {len(org)}')
        if not org:
            violation = f"⛔ No Country (C=) or Organization (O=) value found in {ca_type} CA cert:<br>&emsp;&emsp;▶ <b>{ca_cert.rfc4514_string()}</b>"
            return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, violation)
        else:
            org_name = org[0].value
        
        if ca_org_to_country.get(org_name):
            ca_country = ca_org_to_country[org_name]
        else:
            logging.warning(f"No Country value found in {ca_type} CA cert: {ca_cert.rfc4514_string()}")  # 
            violation = f'ℹ️ No Country (C=) value found in {ca_type} CA cert: <br>&emsp;&emsp;<b>{ca_cert.rfc4514_string()}</b>'
            return ErrorLevel.NOTICE, Finding(DisplayLevel.VERBOSE, func_name(), ErrorLevel.NOTICE.value, violation)
    
    elif len(ca_country) > 1:
        logging.critical(f"Multiple Country values found in {ca_type} CA cert: {ca_cert.rfc4514_string()}")
        violation = f"⛔ Multiple Country (C=) values found in {ca_type} CA cert: <b>{ca_cert.rfc4514_string()}</b>"
        return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, violation)

    logging.info(f"Country attribute for {ca_type} CA:  {ca_country} ")

    if ca_country in config.blocklist:
        violation = f"⛔ {ca_type} CA is located in a <b style='color:red;'>blocklisted</b> country: <b>{config.iso_country_map[ca_country]}</b>"
        logging.error(f'{ca_type} CA for {flow.request.pretty_url} is located in a blocklisted country: {config.iso_country_map[ca_country]}')
        return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, violation)

    if (config.filtering_mode == 'allow' and ca_country not in config.country_list) or (config.filtering_mode == 'warn' and ca_country in config.country_list):
        violation = f"⚠️ {ca_type} CA is located in <strong>{config.iso_country_map[ca_country]}</strong>."
        logging.warning(f'{ca_type} CA is located in: {config.iso_country_map[ca_country]}')
        return ErrorLevel.CRIT, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.CRIT.value, violation)

    if ca_country in config.iso_country_map:
        country_name = config.iso_country_map[ca_country]
    else:
        violation = f"⚠️ The {ca_type} certificate lists an invalid two-letter country code: <b>{ca_country}</b>"
        return ErrorLevel.CRIT, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.CRIT.value, violation)

    violation = f'<span style="color: blue;">&nbsp;🛈</span>&nbsp;&nbsp;Root CA Country: {country_name}.'
    return ErrorLevel.NONE, Finding(DisplayLevel.VERBOSE, func_name(), ErrorLevel.NONE.value, violation)

def controlled_CA_checks(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    """
    Perform controlled certificate authority (CA) checks on the provided root certificate.
    
    This function inspects the subject fields of the root CA (Common Name, Organization,
    and full Distinguished Name) and compares them against configured lists of
    prohibited and restricted root issuers defined in the `config.toml` file.

    ### Args:
        - flow:         The mitmproxy.http.HTTPFlow object associated with the current transaction.
        - cert_chain:   The complete, validated certificate chain for the current TLS connection.

    ### Returns:
        - tuple[ErrorLevel, Optional[str]]:
        A two-element tuple `(ErrorLevel, message)` indicating the result of the check.
            - `ErrorLevel.FATAL`, message — if the root CA is explicitly prohibited.
            - `ErrorLevel.CRIT`, message — if the root CA is restricted.
            - `ErrorLevel.NONE`, `None` — if no restrictions or violations are detected.
    """
    logging.warning("-----------------------------------Entering controlled_CA_checks()--------------------------------")
    identifiers=[]
    
    root = cert_chain[-1]
    root_cn = root.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if root_cn:
        identifiers.append(root_cn[0].value)
    
    root_org = root.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    if root_org:
        identifiers.append(root_org[0].value)

    root_dn = root.subject.rfc4514_string()
    logging.debug(f"Root DN value:                 {root_dn}")
    
    prohibited_value = set(identifiers) & set(config.prohibited_roots)
    restricted_value = set(identifiers) & set(config.restricted_roots)
    
    if prohibited_value:
        violation = f"⛔ Prohibited Root CA detected: <b>{list(prohibited_value)[0]}</b>"
        logging.critical(f'Prohibited Root CA detected: {list(prohibited_value)[0]}')
        return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.CRIT.value, violation)
    elif restricted_value:
        violation = f"⚠️ Restricted Root CA detected: <b>{list(restricted_value)[0]}</b>"
        logging.critical(f"Restricted Root CA detected: '{list(restricted_value)[0]}', issued by {root_org[0].value}.")
        return ErrorLevel.CRIT, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.CRIT.value, violation)
    return ErrorLevel.NONE, None

def expiry_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    """Check if any certificate in the chain is expired."""
    logging.warning("-----------------------------------Entering expiry_check()----------------------------------------")

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
    return ErrorLevel.CRIT, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.CRIT.value, error_message)

def revocation_checks(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    """
    Facade function for performing revocation checking against certificates.
    """
    findings = []
    if not config.revocation_checks:
        logging.warning("Skipping revocation checks per 'revocation_checks' configuration directive.")
        return ErrorLevel.NONE, None
    
    # Check for OCSP data in flow metadata
    stapled_response = False
    if flow.metadata.get("ocsp_response_bytes"):
        stapled_response = flow.metadata.get("ocsp_response_bytes")
    
    is_revoked, error = check_cert_chain_revocation(cert_chain, stapled_response)

    if is_revoked:
        logging.error(f'One or more certificates REVOKED!')
        violation = f"⛔ One or more certs in chain marked as REVOKED:{error}"
        return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, violation)

    if not error:
        findings.append(f'✅ CRL/OCSP revocation checks for all certs in chain came back clean.')
        return ErrorLevel.NONE, Finding(DisplayLevel.POSITIVE, func_name(), ErrorLevel.NONE.value, "<br>".join(findings))

    return ErrorLevel.NOTICE, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.NOTICE.value, error)

def identity_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    """Check if any certificate in the chain lacks a subject, or if the leaf cert lacks a SAN."""
    logging.warning("-----------------------------------Entering identity_check()--------------------------------------")

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
        san_missing_dns = False

        # Only check SAN for the leaf certificate
        if i == 1:
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san_dns_entries = san_ext.value.get_values_for_type(x509.DNSName)
                san_ip_entries = san_ext.value.get_values_for_type(x509.IPAddress)
                if san_ip_entries:
                    logging.warning(f'SubAltName IP Address entries identified: {san_ip_entries}')
                san_missing_dns = len(san_dns_entries) == 0
            except x509.ExtensionNotFound:
                san_missing = True

        # Collect any violations
        if subject_missing or san_missing or san_missing_dns:
            logging.error(
                f"{label} ({cn}) is missing "
                f"{'subject' if subject_missing else ''}"
                f"{' and ' if subject_missing and (san_missing or san_missing_dns) else ''}"
                f"{'SAN' if san_missing else ''}"
                f"{'SAN entry with DNS Name entries' if san_missing_dns else ''}"
            )

            if subject_missing and san_missing:
                violations.append(f'&emsp;&emsp;▶ {label} <code>{cn}</code> is missing both Subject and SubAltName (SAN) extension.')
                error_level = ErrorLevel.CRIT
            elif subject_missing and san_missing_dns:
                violations.append(f'&emsp;&emsp;▶ {label} <code>{cn}</code> is missing both Subject and SubAltName with DNS Name entries.')
                error_level = ErrorLevel.CRIT
            elif subject_missing:
                violations.append(f'&emsp;&emsp;▶ {label} <code>{cn}</code> is missing Subject field.')
                error_level = ErrorLevel.NOTICE
            elif san_missing:
                violations.append(f'&emsp;&emsp;▶ {label} <code>{cn}</code> is missing SubAltName (SAN).')
                error_level = ErrorLevel.WARN
            elif san_missing_dns:
                violations.append(f'&emsp;&emsp;▶ {label} <code>{cn}</code> is missing SubAltName (SAN) with DNS Name entries.')
                error_level = ErrorLevel.WARN

    # Confirm FQDN(s) in leaf cert
    fqdn = (flow.request.pretty_host).lower()
    leaf = cert_chain[0]
    
    cert_domains = get_cert_domains(leaf)
    if len(cert_domains) == 0:
        logging.error(f'No FQDNs found in cert presented when connecting to {fqdn}.')
        error_level = ErrorLevel.FATAL
        violations.append(f'&emsp;&emsp;▶ Certificate for {fqdn} does not contain any FQDNs.')
    
    logging.debug(f'All domains from leaf cert: {cert_domains}')

    # Build list of applicable FQDNs from cert to check against
    check_domains=[]
    if fqdn in cert_domains:
        check_domains.append(fqdn)
        
    # Check to see if FQDN in URL is handled via wildcard entry in cert
    fqdn_parts=fqdn.split(".")
    if len(fqdn_parts) > 2:
        base_domain = ".".join(fqdn_parts[1:])
        logging.info(f' Base domain: {base_domain}')
        if f'*.{base_domain}' in cert_domains:
            check_domains.append(f'*.{base_domain}')

    # Raise error if URL FQDN not present in list
    if len(check_domains) == 0:
        logging.error(f'Certificate not valid for FQDN of {fqdn}.')
        error_level = ErrorLevel.CRIT
        violations.append(f'&emsp;&emsp;▶ Certificate <a href=https://knowledge.digicert.com/solution/name-mismatch-in-web-browser target="_blank">name mismatch</a>; cert not valid for <code>{fqdn}</code>.')

    # Write FQDN list to flow metadata for use by other functions
    flow.metadata["cert_domains"] = check_domains    

    if not violations:
        logging.debug('Cert identity checks completed successfully.')
        return ErrorLevel.NONE, None

    if error_level == ErrorLevel.FATAL:
        error_message = f'⛔ Critical identity issue(s) found in certificate chain:<br>{"<br>".join(violations)}'
        dp_level = DisplayLevel.CRITICAL
    else:
        error_message = f'⚠️ Identity issue(s) found in certificate chain:<br>{"<br>".join(violations)}'
        dp_level = DisplayLevel.WARNING
    
    return error_level, Finding(dp_level, func_name(), error_level.value, error_message)

def critical_ext_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    """
    Confirm that no unrecognized x.509 extension marked as critical exists within the certificate chain.
    """
    unrecognized = False
    unknowns = []
    for i, cert in enumerate(cert_chain):
        for ext in cert.extensions:
            if ext.critical and isinstance(ext.value, x509.UnrecognizedExtension):
                unrecognized = True
                oid: x509.ObjectIdentifier = ext.oid.dotted_string
                # ext.value.value is the raw bytes of the extension
                raw = ext.value.value
                logging.critical(f"Unknown critical X.509 extension found in cert #{i} ({cert.subject.rfc4514_string})")
                logging.critical(f"   OID: {oid.dotted_string}    Extension hex data (truncated to 200 bytes): {raw.hex()[:200]}")
                unknowns.append(f"<br>&emsp;&emsp;▶ Cert #{i}, Unrecognized OID: <code>{oid}</code>")
    if unrecognized:
        error = f"⛔ Unknown critical X.509 extension(s) found in cert chain:"
        violation = error + "".join(unknowns)
        return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, violation)
    else:
        logging.debug("No unrecognized x.509 extensions marked as 'Critical' found.")
        return ErrorLevel.NONE, None

def prior_approval_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate], quick_check: bool=False) -> bool | Tuple[ErrorLevel, Optional[Finding]]:
    """
    Check whether the given host and root certificate have been previously approved,
    or if a root CA change has occurred since the last recorded decision.

    This function consults the local SQLite database to determine whether the
    host has a prior approval record and whether the associated root certificate
    fingerprint matches the stored record.

    Args:
        flow:           The mitmproxy.http.HTTPFlow object representing the transaction (used to extract the host).
        cert_chain:     The complete, validated certificate chain for the current TLS connection.
        quick_check:    If True, perform a fast lookup to confirm whether the host and root
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
    logging.warning("-----------------------------------Entering prior_approval_check()--------------------------------")
    # If refactor this function as a class, can persist the 'row' value below so there's only one SQL query
    host = flow.request.pretty_host
    #if approved_hosts:
        #logging.info(f'Approved hosts: {approved_hosts}')

    root_fingerprint = cert_chain[-1].fingerprint(hashes.SHA256()).hex()
    
    # TODO: Extend this to examine additional root cert parameters.
    with sqlite3.connect(config.db_path) as conn:
        row = conn.execute("SELECT decision, root FROM decisions WHERE host = ?", (host,)).fetchone()               
        
        if quick_check == True:
            logging.info('Performing initial quick check...')
            logging.debug(f'Existing database record for {host}: {row}')
            if row and row[0] == "approved" and row[1] == root_fingerprint:
                logging.info(f"Root CA for {host} remains consistent with previously approved record in database; skipping further checks.")
                return True
            else:
                if not row:
                    logging.info(f"No record for {host} found in database; proceeding with further checks.")
                return False
        
        elif quick_check == False:  # Note - Should never get to this code path on subsequent function call if the earlier check above returned True.
            logging.info('Performing second-pass check for root cert drift in database.')
            #if row and row[0] == "approved" and row[1] != root_fingerprint:
            if row and row[1] != root_fingerprint:
                logging.info(f"Root CA for {host} inconsistent with previously observed!")   
                violation = f"❌ Root CA for <b>{host}</b> inconsistent with previously observed!"
                return ErrorLevel.CRIT, Finding(DisplayLevel.TOPLEVEL, func_name(), ErrorLevel.CRIT.value, violation)
            logging.info(f"No mismatched root CA records found for {host} in database.")   
        return ErrorLevel.NONE, None   # Assumes no row returned, or consistent root_fingerprint 

def sct_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    logging.warning("-----------------------------------Entering sct_check()-------------------------------------------")
    
    # Skip SCT checks
    if len(cert_chain) == 1:
        logging.warning('Skipping SCT checks due to incomplete cert chain or self-signed certificate.')
        return ErrorLevel.NONE, None

    cert = cert_chain[0]
    issuer_cert = cert_chain[1]

    warnings = []
    violations = []
    logging.info(f'Input cert: {cert.subject.rfc4514_string()}')
    logging.debug(f'Issuer cert: {issuer_cert.subject.rfc4514_string()}')
    
    # Check for SCTs & extract data
    scts = extract_scts(cert, ct_log_map)
    if not scts:
        # TODO: Update code to account for external SCTs (e.g. delivered via OCSP or during TLS negotation).  Although these
        # alternative SCT delivery methods are exceedingly rare, this check should not result in FATAL errors until those methods are added.
        logging.error(f"Cert for {flow.request.pretty_url} missing SCT(s)!")
        violation = '⚠️ Certificate missing <a href=https://certificate.transparency.dev/howctworks/ target="_blank">Signed Certificate Timestamps</a> (SCTs).'
        return ErrorLevel.ERROR, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.ERROR.value, violation)
    
    # Print out SCT details for debugging purposes
    for i, sct in enumerate(scts, 1):
        logging.debug(f"SCT #{i}")
        for k, v in sct.items():
            logging.debug(f"  {k}: {v}")
        if sct["extension_bytes"] != '':
            logging.warning('  SCT extensions found')
            logging.debug(bytes.fromhex(sct["extension_bytes"]))
        
        # Validate SCT digital signatures (if enabled)
        if config.verify_signatures:
            validated, error, leaf_struct = validate_sct_signature(cert, issuer_cert, sct)
            if error:
                logging.error(f"Error during SCT validation attempt for SCT #{i}: {error}")
                warnings.append(f'⚠️ Encountered error trying to validate SCT #{i}: {error}')
            elif not validated:
                logging.error(f"SCT signature #{i} FAILED to validate!")
                violations.append(f'⛔ Digital signature validation for <a href=https://certificate.transparency.dev/howctworks/ target="_blank">SCT</a> #{i} failed.')
            else:
                logging.info(f" SCT #{i} digital signature verified")

        # Cryptographically audit CT log inclusion (if enabled)
        if validated and config.verify_inclusion:
            included, error = verify_inclusion(leaf_struct, sct["ct_log_url"], sct["timestamp_unix"], sct["ct_log_mmd"])
            if included:
                logging.info(f" Inclusion in {sct["ct_log_description"]} verified")    
            else:
                warnings.append(f'⚠️ {error}')

    if violations:
        return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, f'{"<br>".join(violations)}')
    elif warnings:
        return ErrorLevel.ERROR, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.ERROR.value, f'{"<br>".join(warnings)}')
    else:
        return ErrorLevel.NONE, Finding(DisplayLevel.POSITIVE, func_name(), ErrorLevel.NONE.value, f'✅ SCT signatures valid; inclusion verified for {len(scts)} CT logs.')

def ct_quick_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    """
    Make call to SSLMate to check for cert/precert inclusion in Certificate Transparency log(s) and cert revocation.
    LIMITATION: SSLMate purges expired certificates, so if cert is expired this check is bypassed.
    """
    logging.warning("-----------------------------------Entering ct_quick_check()--------------------------------------")

    if not config.quick_check:
        return ErrorLevel.NONE, None

    else:
        cert = cert_chain[0]
        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        
        if now > not_after:
            logging.info('Skipping SSLMate lookup since leaf certificate has expired.')
            return ErrorLevel.NONE, None

        violations = []
        found, revoked, error = ctlog_quick_check(flow, cert)

        if error:
            logging.error(f'Could not check SSLMate for Certificate Transparency inclusion: {error}.')
            return ErrorLevel.ERROR, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.ERROR.value, f'{error}')

        if found:
            logging.info(f'Publication in Certificate Transparency log confirmed.')
        else:
            not_before = cert.not_valid_before_utc
            logging.info(f'Leaf cert not_valid_before date (UTC): {not_before}')
            
            if now - timedelta(hours=24) < not_before <= now:
                logging.info('Cert is within Maximum Merge Delay (MMD) window for publishing to Certificate Transparency log.')
                return ErrorLevel.INFO, Finding(DisplayLevel.VERBOSE, func_name(), ErrorLevel.INFO.value, f'<span style="color: blue;">&nbsp;🛈</span>&nbsp;&nbsp;Cert not found in CT logs, but within 24hr <a href=https://datatracker.ietf.org/doc/html/rfc6962#section-3 target="_blank">Maximum Merge Delay</a> period.')

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
            return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, f'{"<br>".join(violations)}')

        return ErrorLevel.NONE, Finding(DisplayLevel.POSITIVE, func_name(), ErrorLevel.NONE.value, f'✅ CT log inclusion checked via SSLMate and certificate not marked as revoked')

def caa_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    """ 
    For each FQDN in the cert, verify if the issuing CA is authorized via CAA.  Supports both 'issue' and 'issuewild' tags.  Returns a dictionary in the form of {domain: allowed}.

    Args:
        flow:       The mitmproxy.http.HTTPFlow object the current HTTP request.
        cert_chain: The complete, validated certificate chain for the current TLS connection.

    Returns:
        tuple[ErrorLevel, str]: A tuple consisting of the ErrorLevel (based on the verdict for the CAA verification logic) and, if applicable, a string 
        capturing the violation(s) encountered.
    """
    logging.warning("-----------------------------------Entering verify_cert_caa()-------------------------------------")

    x509_leaf = cert_chain[0]
    fqdn = (flow.request.pretty_host).lower()
    orgs=[]
    for attr in x509_leaf.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME):
        org = attr.value
        orgs.append(org)
        logging.info(f' Extracted Organization for Issuing CA Cert:  O="{org}"')
    
    if not orgs:
        logging.error(f'No Organization (O=) value identified for Issuing CA.  Bypassing curther CAA checks.')
        return ErrorLevel.WARN, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.WARN.value, f'⚠️ No Organization (O=) value found for Issuing CA.')

    if len(orgs) >= 2:
        logging.info(f' Multiple Orgs found in Issuing CA: {orgs}')
        return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, f'⛔ Multiple Organization values encountered inside Issuing CA cert! <b>{",".join(orgs)}</b>')
    
    ca_identifiers=ca_org_to_caa.get(org, ["UNKNOWN issue-domain-name identifier!  Please update 'ca_org_mapping.py' file"]) 
    logging.info(f' Matching CA identifiers: {ca_identifiers}')

    cert_domains = flow.metadata.get("cert_domains")
    
    # Silently exit if no FQDNs extracted from cert; let identity_check() handle related errors.
    if not cert_domains:
        return ErrorLevel.NONE, None
    else:
        check_domains = cert_domains

    logging.info(f' Checking CAA records for domains {check_domains}')

    results = {}
    for domain in check_domains:
        results[domain], other_errors, records_found = check_caa_per_domain(config, domain, ca_identifiers)
    logging.info(f'Results from check_caa_per_domain(): {results}')

    caa_violations=[]
    return_violations=[]
    for domain, allowed in results.items():
        if not allowed:
            logging.critical(f'FQDN in cert not authorized by CAA record: {domain}')
            caa_violations.append(domain)

    if not records_found:
        return ErrorLevel.NONE, Finding(DisplayLevel.VERBOSE, func_name(), ErrorLevel.NONE.value, f'<span style="color: blue;">&nbsp;🛈</span>&nbsp;&nbsp;No published CAA records identified.')

    if caa_violations:
        return_violations.append(f'⚠️ FQDN(s) in cert not authorized by CAA record: <b>{",".join(caa_violations)}</b>')
    
    if other_errors:
        return_violations.append(f'⚠️ Issues encountered during <a href=https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization target="_blank">CAA</a> verification:<br>    {other_errors}')

    if return_violations:
        return ErrorLevel.WARN, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.WARN.value, f'{"<br>".join(return_violations)}')
    else:
        return ErrorLevel.NONE, Finding(DisplayLevel.POSITIVE, func_name(), ErrorLevel.NONE.value, f'✅ CAA records successfuly validated.')

def test_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    # Modified example rule from mitmproxy documentation
    logging.warning("-----------------------------------Entering test_check()------------------------------------------")
    if "https://www.example.com/path" in flow.request.pretty_url:
        logging.info("Triggered test_check().")
        violation = f'<span style="color: green;">&nbsp;🛈</span>&nbsp;&nbsp;Example URL accessed: <b>{flow.request.pretty_url}</b>.'
        return ErrorLevel.INFO, Finding(DisplayLevel.WARNING, func_name(), ErrorLevel.INFO.value, violation)
    return ErrorLevel.NONE, None

def dane_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    """Check for DANE TLSA records and, if found, validate server certificate per RFC 6698"""
    logging.warning(f"-----------------------------------Entering dane_check()------------------------------------------")
    
    if flow.server_conn.tls:
        logging.debug(f'Flow Connection:         {flow.server_conn}')
        dane_validator.perform_dane_check(flow.server_conn, cert_chain)
        
    logging.debug(f'dane_validator.dnssec_failure: {dane_validator.dnssec_failure}')
    logging.debug(f'dane_validator.dane_failure:   {dane_validator.dane_failure}')
    logging.debug(f'dane_validator.violation:      {dane_validator.violation}')

    if not dane_validator.dane_used:
        return ErrorLevel.NONE, None
    else: # DANE in use
        if dane_validator.dane_validated:
            return ErrorLevel.NONE, Finding(DisplayLevel.POSITIVE, func_name(), ErrorLevel.NONE.value, f'✅ DANE TLSA Record successfuly validated.')
        elif dane_validator.dane_failure == True and config.enforce_dane:
            logging.error("Blocking request per 'enforce_dane' configuration.")
            return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, f'{dane_validator.violation}')
        elif dane_validator.dnssec_failure == True and config.require_dnssec:
            logging.error("Blocking request per 'enforce_dnssec' configuration.")
            return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, f'{dane_validator.violation}')
        else:
            return ErrorLevel.CRIT, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.CRIT.value, f'{dane_validator.violation}')

def dnssec_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Finding]:
    logging.warning(f"-----------------------------------Entering dnssec_check()----------------------------------------")
    if dane_validator.authenticated_data:     # Save an additional DNS lookup by leveraging the existing DANE TLSA record check.
        logging.debug('DNSSEC is enabled for zone.')
        return ErrorLevel.NONE, Finding(DisplayLevel.POSITIVE, func_name(), ErrorLevel.NONE.value, f'✅ The DNS zone is DNSSEC-signed and has a valid chain of trust.')
    else:
        logging.debug('DNSSEC is not enabled for zone.')
        return ErrorLevel.NONE, Finding(DisplayLevel.VERBOSE, func_name(), ErrorLevel.NONE.value, f'&nbsp;✘&nbsp;&nbsp;The DNS zone is not DNSSEC-signed.')

def x509_version_check(flow: http.HTTPFlow, cert_chain: list[x509.Certificate]) -> Tuple[ErrorLevel, Optional[Finding]]:
    """
    Check all certs in the provided cert chain for any cert with an x.509 version number less than v3.

    Note: The cryptography library represents versions as an enum-like object:
        x509.Version.v1  -> 0
        x509.Version.v2  -> 1
        x509.Version.v3  -> 2
    ...But actual X.509 versions are 1, 2, 3 respectively.
    """
    violations = []

    for i, cert in enumerate(cert_chain):
        cryptography_version_value = cert.version.value

        # Convert to X.509 version numbers (1, 2, 3)
        x509_version = cryptography_version_value + 1
    
        if x509_version < 3:
            if i == 0:
                violations.append(f'⛔ Server certificate is an x509v{x509_version} cert!')
            else:
                violations.append(f'⛔ Certificate #{i} in chain is an x509v<b>{x509_version}</b> cert.')

    if violations:
        return ErrorLevel.FATAL, Finding(DisplayLevel.CRITICAL, func_name(), ErrorLevel.FATAL.value, "<br".join(violations))
    else:
        return ErrorLevel.NONE, None
