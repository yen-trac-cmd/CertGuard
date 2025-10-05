from ca_org_mapping import ca_org_to_caa
from collections import deque
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa, padding
from datetime import datetime, timedelta, timezone
from dns.rdtypes.ANY import CAA
from enum import Enum
from error_screen import error_screen
from helper_functions import cert_to_x509, get_cert_domains, supported_ciphers_list
from mitmproxy import ctx, http
from urllib.parse import urlparse
import certifi
import dns.resolver
import json
import ipaddress
import logging                          # Valid levels = debug, info, warning, error, critical, fatal.  
import os
import sqlite3
import sys
import tomllib
import uuid
import verify_SCTs

with open("config.toml", "rb") as f:
    config = tomllib.load(f)
logging_level     = config["general"]["logging_level"].lower()              # "debug", "info", "warn", "error", or "alert"
user_resolvers    = config["general"]["resolvers"]
dns_timeout       = config["general"]["dns_timeout"]
db_path           = config["general"]["db_path"]
intercept_mode    = config["general"]["intercept_mode"].lower()             # "compatible" or "strict"
token_mode        = config["general"]["token_mode"].lower()                 # "header", "get", or "post"
exempt_eTLDs      = config["caa_exceptions"]["exempt_eTLDs"]
filtering_mode    = config["country_filtering"]["filtering_mode"].lower()   # "allow" or "warn"
restricted_roots  = config["controlled_roots"]["restricted_roots"]
prohibited_roots  = config["controlled_roots"]["prohibited_roots"]
verify_signatures = config["sct_config"]["verify_signatures"]
country_list      = [country.upper() for country in config["country_filtering"]["country_list"]]
blocklist         = [country.upper() for country in config["country_filtering"]["blocklist"]]

# Handle optional config parameters:
try: 
    custom_roots_dir = config["general"]["custom_roots_dir"]
except:
    custom_roots_dir = None
try:
    min_tls_version  = config["tls_config"]["min_tls_version"]
except:
    min_tls_version  = 1.2
try:
    ciphersuites     = config["tls_config"]["ciphersuites"].upper()
except:
    ciphersuites     = None

resolver = dns.resolver.Resolver()
for ip in user_resolvers:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logging.fatal(f"Invalid DNS resolver entry in config.toml: {ip}")
resolvers = deque(user_resolvers)

with open('iso-3166-alpha2_list.json') as iso_countries:
    iso_country_map = json.load(iso_countries)

public_suffix_list = []
# TODO: Add a check to fetch new 'public_suffix_list.dat' from https://publicsuffix.org/list/public_suffix_list.dat if local copy is >5 days old.
#       Can reuse code from verify_SCTs.load_ct_log_list()
try:
    with open('public_suffix_list.dat', 'r', encoding='utf-8') as psl:
        for line in psl:
            if not line.strip().startswith('//') and line.strip():
                public_suffix_list.append(line.strip())
except FileNotFoundError:
    logging.fatal(f"FATAL Error: Cannot locate public_suffix_list.dat in the current directory!")


def get_root_store():
    # Load trusted roots from certifi
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
    if custom_roots_dir == None:
        pass
    else:
        from glob import glob
        if os.path.isdir(custom_roots_dir):
            pem_files = glob(os.path.join(custom_roots_dir, '*.pem'))
            logging.info(f'Loading {len(pem_files)} custom root files from {custom_roots_dir}.')
            for file in pem_files:
                with open(file, "rb") as f:
                    root_bundle += f.read()
        else:
            logging.fatal(f"Could not find directory specified for 'custom_roots_dir': {custom_roots_dir}.")
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

def load(loader):
    if logging_level in ["debug", "info", "warn", "error", "alert"]:
        opts = ctx.options.keys()
        if "console_eventlog_verbosity" in opts:
            # Running in mitmproxy console UI
            ctx.log.info("Detected mitmproxy console UI")
            ctx.options.console_eventlog_verbosity = logging_level
        else:
            # Running in mitmdump (or mitmweb)
            ctx.log.info("Detected mitmdump/mitmweb")
            ctx.options.termlog_verbosity = logging_level
    else:
        logging.warning(f"Invalid console logging mode defined in config.toml; defaulting to 'info' level.")
    
    if type(dns_timeout) != float:
        logging.fatal(f"dns_timeout in config.toml must be configured as floating point value!")

    if filtering_mode not in ['allow', 'warn']:
        logging.fatal(f"Invalid country filtering mode defined in config.toml!")

    if intercept_mode not in ['compatible', 'strict']:
        logging.fatal(f"Invalid 'intercept_mode' defined in config.toml!")

    if token_mode not in ['header', 'post', 'get']:
        logging.fatal(f"Invalid 'token_mode' defined in config.toml!")

    for entries in [country_list, blocklist]:
        if not all(isinstance(country, str) and len(country) == 2 for country in entries):
            raise AssertionError("All countries in config.toml must be specified as 2-character iso-3166-alpha2 codes!")
        
        unrecognized = [entry for entry in entries if entry not in iso_country_map]
        assert not unrecognized, f"Unrecognized country specified in config.toml: {unrecognized}!"

    match min_tls_version:
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

    if ciphersuites == None:
        pass
    else:
        supported_ciphers = supported_ciphers_list()
        target_ciphers = []
        for cipher in ciphersuites.split(':'):
            if cipher in supported_ciphers:
                target_ciphers.append(cipher)
        ctx.options.ciphers_server = ":".join(target_ciphers)
        logging.debug(f'Configured ciphers: \n* {"\n* ".join(target_ciphers)}')

    # Create SQLite DB and table if not exists
    with sqlite3.connect(db_path) as conn:
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

class ErrorLevel(Enum):
    NONE   = 0
    INFO   = 1
    NOTICE = 2
    WARN   = 3
    ERROR  = 4
    CRIT   = 5
    FATAL  = 6
    
PAGE_COLOR = {
    ErrorLevel.INFO:   'Green',
    ErrorLevel.NOTICE: 'Blue', 
    ErrorLevel.WARN:   'Yellow', 
    ErrorLevel.ERROR:  'Orange', 
    ErrorLevel.CRIT:   'Red', 
    ErrorLevel.FATAL:  'Maroon',
}

def verify_signature(subject: x509.Certificate, issuer: x509.Certificate):
    #Cryptographically verify that `issuer` signed `subject`.
    #Handles RSA (PKCS#1 v1.5 and basic PSS), ECDSA, Ed25519/Ed448, and DSA.
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

def get_cdp(cert):
    crl_urls = []
    try:
        crl_dp_extension = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        )
        crl_value=crl_dp_extension.value

        for distribution_point in crl_value:
            if distribution_point.full_name:
                for general_name in distribution_point.full_name:
                    if isinstance(general_name, x509.UniformResourceIdentifier):
                        crl_urls.append(general_name.value)

    except x509.ExtensionNotFound:
        logging.warning(f'No CRL Distribution Point found in cert!')
        return []
    
    return crl_urls

def get_root_cert(chain, root_store):
    # Given an HTTPS mitmproxy flow, attempt to resolve and verify the root CA certificate for the server's certificate chain.
    # Returns root_cert object (cryptography.x509.Certificate) or None if not found/verified

    # Convert mitmproxy Cert object to cryptography.x509.Certificate
    server_chain = [cert_to_x509(cert) for cert in chain]
    
    logging.info(f'Number of certifi + custom trusted root CA entries: {len(root_store)}')

    # Verify each link in the chain, starting from leaf and working up to the last interemediate CA cert
    for issuer, subject in zip(server_chain[1:], server_chain[:-1]):
        try:
            verify_signature(subject, issuer)
            logging.info(f"Initial chain verification successful.")
        except Exception as e:
            logging.critical(f"Initial chain verification failed between '{subject.subject.rfc4514_string()}' and '{issuer.subject.rfc4514_string()}': {e}")
            logging.critical(f"Aborting further verification attempts.")
            return None, None
            
    # Verify last cert in chain against a trusted root anchors 
    last_cert = server_chain[-1]
    cdp=get_cdp(server_chain[0])                                #  This eventually needs moved to its own check...  ###########
    logging.info(f'Length of presented chain:       {len(server_chain)}')
    logging.warning(f"LEAF cert CDP value(s):          {cdp}")  #  This eventually needs moved to its own check...  #######################
    logging.warning(f"LEAF cert subject:               {server_chain[0].subject.rfc4514_string()}")
    logging.warning(f"LEAF cert issuer:                {server_chain[0].issuer.rfc4514_string()}")
    logging.warning(f"LEAF cert not valid before:      {server_chain[0].not_valid_before_utc}")
    logging.warning(f"LEAF cert not valid after:       {server_chain[0].not_valid_after_utc}")
    logging.debug(f"LEAF cert serial number:        {server_chain[0].serial_number}")
    logging.debug(f"LEAF cert fingerprint:          {(server_chain[0].fingerprint(hashes.SHA256())).hex()}")
    if len(server_chain) > 1:
        logging.info(f"Issuing CA Subject:              {last_cert.subject.rfc4514_string()}")
        logging.info(f"Issuing CA Issuer:               {last_cert.issuer.rfc4514_string()}")
        logging.debug(f"Issuing CA serial number:       {last_cert.serial_number}")
        logging.info(f"Issuing CA not valid before UTC: {last_cert.not_valid_before_utc}")
        logging.info(f"Issuing CA not valid after UTC:  {last_cert.not_valid_after_utc}")
        logging.debug(f"Issuing CA fingerprint:          {(last_cert.fingerprint(hashes.SHA256())).hex()}")
        
    for root in root_store:
        if root.subject == last_cert.issuer:
            try:
                verify_signature(last_cert, root)
                logging.info(f'Chain verified against root CA:  {root.subject.rfc4514_string()}')
                logging.info(f'Root cert fingerprint:           {(root.fingerprint(hashes.SHA256())).hex()}')
                return root, None
            except Exception as e:
                logging.fatal(f"Root CA cert verification failed: {e}")
                continue
    
    logging.fatal(f"No trust anchor cert found!")

    try:
        return None, last_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except:
        return None, last_cert.issuer.rfc4514_string()

def root_country_check(flow, root):
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

        if root_country in blocklist:
            violation = f"⛔ Root CA is located in a <b style='color:red;'>blocklisted</b> country: <b>{iso_country_map[root_country]}</b>"
            logging.error(f'Root CA for {flow.request.pretty_url} is located in a blocklisted country: {iso_country_map[root_country]}')
            return ErrorLevel.FATAL, violation

        if (filtering_mode == 'allow' and root_country not in country_list) or (filtering_mode == 'warn' and root_country in country_list):
            violation = f"⚠️ Root CA is located in <strong>{iso_country_map[root_country]}</strong>."
            logging.warning(f'Root CA is located in: {iso_country_map[root_country]}')
            return ErrorLevel.CRIT, violation
            
    return ErrorLevel.NONE, None

def controlled_CA_checks(flow, root):
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
    
    prohibited_value = set(identifiers) & set(prohibited_roots)
    restricted_value = set(identifiers) & set(restricted_roots)
    
    if prohibited_value:
        violation = f"⛔ Prohibited Root CA detected: <b>{list(prohibited_value)[0]}</b>"
        logging.fatal(f'Prohibited Root CA detected: {list(prohibited_value)[0]}')
        return ErrorLevel.FATAL, violation
    elif restricted_value:
        violation = f"⚠️ Restricted Root CA detected: <b>{list(restricted_value)[0]}</b>"
        logging.fatal(f"Restricted Root CA detected: '{list(restricted_value)[0]}', issued by {root_org[0].value}.")
        return ErrorLevel.CRIT, violation
    return ErrorLevel.NONE, None

def example_check(flow, root):
    # Modified example rule from mitmproxy documentation
    if "https://www.example.com/path" in flow.request.pretty_url:
        logging.info(".-=Triggered Example Auto-Response=-.")
        violation = f'<span style="color: green;">&nbsp🛈</span>&nbsp&nbspExample URL accessed: <b>{flow.request.pretty_url}</b>.'
        return ErrorLevel.INFO, violation
    return ErrorLevel.NONE, None

def verify_cert_caa(flow, root) -> dict[str, bool]:
    logging.warning(f"-----------------------------------Entering verify_cert_caa()---------------------------------------------")
    # For each FQDN in the cert, verify if the issuing CA is authorized via CAA.
    # Supports both 'issue' and 'issuewild' tags.  Returns a dictionary in the form of {domain: allowed}.
    
    leaf = flow.server_conn.certificate_list[0]
    x509_leaf = cert_to_x509(leaf)
    
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

    cert_domains = get_cert_domains(x509_leaf)    # Gets all SANs in cert.  We won't check against all, but this lets us check for wildcard entries.
    logging.debug(f'All domains from leaf cert: {cert_domains}')
    
    check_domains=[]
    fqdn = (flow.request.pretty_host).lower()
    lower_case_cert_domains = [fqdn.lower() for fqdn in cert_domains]
    if fqdn in lower_case_cert_domains:
        check_domains.append(fqdn)
        
    # Check to see if FQDN in URL is handled via wildcard entry in cert
    fqdn_parts=fqdn.split(".")
    if len(fqdn_parts) > 2:
        base_domain = ".".join(fqdn_parts[1:])
        logging.info(f' base_domain(): {base_domain}')
        if f'*.{base_domain}' in cert_domains:
            check_domains.append(f'*.{base_domain}')

    logging.info(f' Checking CAA records for these domains = {check_domains}')

    #################### call is_zoned_signed() from here against 'fqdn'??????????????
    ############## Need to walk to SOA to check for DNSKEY against the entire zone???
    ######### Or do I just want to know if the CAA record comes back with matching RRSIG record???  ...I think so.

    #domain_signed = is_zone_signed(fqdn)
    #logging.warning(f'DNS zone signed? {domain_signed}')

    results = {}
    for domain in check_domains:
        results[domain], other_errors = check_caa_per_domain(domain, ca_identifiers)
    logging.info(f'Results from check_caa_per_domain(): {results}')

    caa_violations=[]
    return_violations=[]
    for domain, allowed in results.items():
        if not allowed:
            logging.critical(f'FQDN in cert not authorized by CAA record: {domain}')
            caa_violations.append(domain)

    if caa_violations:
        return_violations.append(f'⚠️ FQDN(s) in cert not authorized by CAA record: <b>{",".join(caa_violations)}</b>')
    if other_errors:
        return_violations.append(f'⚠️ Critical condition(s) encountered during <a href=https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization target="_blank">CAA</a> verification:<br>    {other_errors}')

    if return_violations:
        return ErrorLevel.WARN, f'{"<br>".join(return_violations)}' 

    return ErrorLevel.NONE, None
    
def is_zone_signed(domain):           ##################### issue is that I'm looking for NS records against subdomains...  don't
    logging.warning(f"===================================Entering is_zone_signed()========================================")
    ######## will DNS *always* return SOA with any query for non-existent record?  If so, chase that.  ...If not, do devolution thing to get SOA.  ...THEN query for NS.
    try:
        ns_query = dns.resolver.query(domain, dns.rdatatype.NS)
        logging.error(f'ns_query response when checking against "{domain}": {str(ns_query[0])}')

        nameserver = str(ns_query[0])
        logging.info(f"Authoritative nameserver '{nameserver}'' found for domain '{domain}'.")

        # Query the authoritative nameserver for DNSKEY records to determine if zone is signed
        nameserver_ip = dns.resolver.query(nameserver, dns.rdatatype.A)[0].to_text()
        query_message = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.udp(query_message, nameserver_ip)
            
        if response.answer and any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer):
            logging.info(f"The {domain} zone appears to be DNSSEC-signed (found RRSIG records).")
            return True
        else:
            logging.info(f"The zone {domain} zone does NOT appear to be DNSSEC-signed (no RRSIG records found).")
            return False
                
    except dns.resolver.NXDOMAIN:
        logging.error(f"Error: The {domain} domain does not exist.")
        return False
    except dns.resolver.NoAnswer:
        logging.error(f"Warning: No NS records found for '{domain}', or no DNSKEY records returned.")
        return False
    except dns.exception.Timeout:
        logging.error(f"Error: DNS query for {domain} timed out.")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False

def check_caa_per_domain(domain: str, ca_identifiers: list[str]) -> bool:
    logging.warning(f"-----------------------------------Entering check_caa_per_domain()----------------------------------------")
    # Check CAA records for the given domain.
    is_wildcard = domain.startswith("*.")

    if is_wildcard:
        logging.info(f' Checking wildcard domain: {domain}')
    else:
        logging.info(f' Checking NON-wildcard domain: {domain}')
    
    labels = domain.lstrip("*.").split(".")     #  Strip wildcard prefix if present

    etld = False 
    for i in range(len(labels)):  # Climb the DNS tree checking for applicable CAA record(s), warn if only found at TLD level.
        check_domain = ".".join(labels[i:])
        #logging.info(f' Check being performed against domain: {check_domain}')
        logging.warning(f' Checking for DNS CAA records published at {check_domain} against enumerated CA identifiers: {ca_identifiers}')
        
        # Check to see if comparing against an "effective TLD" / public suffix, with exceptions as defined in config.toml.
        # See https://developer.mozilla.org/en-US/docs/Glossary/eTLD and https://publicsuffix.org/ for reference
        if check_domain in public_suffix_list and not check_domain in exempt_eTLDs: etld = True 
        #if len(check_domain.split("."))==1: etld = True   # Initial simplistic check that only accounted for true single-label TLDs.

        ############################################################################################ this needs to move out once I figure out right structure
        #domain_signed = is_zone_signed(check_domain)
        #logging.warning(f'DNS zone signed? {domain_signed}')

        #if domain_signed:
        #    logging.warning(f'True or fasle: {domain_signed}')
        try:
            current_resolver = resolvers[0]
            logging.debug(f'   Using resolver: {current_resolver}')

            query = dns.message.make_query(check_domain, dns.rdatatype.CAA, want_dnssec=True)
            got_response=False
            while got_response==False:
                try:
                    answers = dns.query.udp_with_fallback(query, current_resolver, timeout=dns_timeout)  # timeout parameter is required, otherwise mitmproxy can freeze
                    got_response=True
                except dns.exception.Timeout as e:
                    resolvers.rotate(1)
                    current_resolver = resolvers[0]
                    logging.error(f'DNS query using resolver {resolvers[-1]} for "{check_domain}" timed out!!  ...Trying again with resolver {current_resolver}.')
            
            if answers[1]:
                logging.warning(f'DNS query had to fallback to TCP due to truncated response')
            
            answers=answers[0]
            #logging.info(f'DNS Response flags: {answers.flags}')
            logging.debug(f'Full resource record set: {answers}')
           
            #if domain_signed:
            if answers.flags & dns.flags.AD:   # Indicates a DNSSEC-validated resposne; dns.flags.AD = 32
                logging.info(f'DNSSEEC validation successful (AD bit set in response).')
            else:
                logging.fatal(f'DNSSEEC validation for {check_domain} failed.')         #### Ideally structured to raise FATAL on failed DNSSEC validation for signed zone.

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
                        if len(issuewild_properties) == 1 and issuewild_properties[0] == ";":  # CAA records are additive, so need to ensure blank record is by itself.
                            return False, f'Wildcard certificate issuance explicitly prohibited for {domain}!' 
                        for ca in ca_identifiers:
                            for ca_entry in issuewild_properties:
                                if ca in ca_entry:    # Important to use 'in' since issue tags can have extension properties specified by Certification Authory.
                                        if etld:
                                            logging.error(f'Authorizing wildcard CAA record (<code>{ca}</code>) *only* found at .{check_domain} eTLD!')    
                                            return True, f"&emsp;&nbsp;&nbsp;&nbsp;Wildcard CAA record ({ca}) <u>only</u> found at <b>.{check_domain}</b> eTLD!"
                                        logging.warning(f"SUCCESS: Wildcard CA from mapping ({ca}) matched CAA record published at {check_domain}.")
                                        return True, None
                
                # Fallthrough -- Either we're testing a non-wildcard cert entry OR we're testing a wildcard cert but there's no 'issuewild' property.
                if not issue_properties:
                    logging.warning(f" No 'issue' CAA records found at {check_domain}.")
                    continue
                if len(issue_properties) == 1 and issue_properties[0] == ";":  # CAA records are additive, so need to ensure blank record is by itself.
                    return False, f'Empty issuer-domain-name value (";") encountered at {check_domain}; certificate issuance explicitly prohibited for {domain}!' 
                
                logging.debug(f"'issue' properties values from CAA records: {issue_properties}")
                for ca in ca_identifiers:
                    logging.debug(f"Checking against mapped issuer-domain-name: {ca}")
                    for ca_entry in issue_properties:
                        if ca in ca_entry:    # Important to use 'in' since issue tags can have extension properties specified by Certification Authory.
                                if etld:
                                    logging.error(f"Authorizing CAA record ({ca}) only found at .{check_domain} eTLD!")    
                                    return True, f'&emsp;&nbsp;&nbsp;&nbsp;Matching CAA record (<code>{ca}</code>) <em>only</em> found at <b>.{check_domain}</b> eTLD!'
                                logging.warning(f"SUCCESS: CA from mapping ({ca}) matched CAA record published at {check_domain}.")
                                return True, None

        else:  # No answer rdata retrieved from CAA query
            logging.info(f'No published CAA record found at {check_domain}.')
            continue
    
    logging.warning(f'No published CAA record found; return true per RFC8659')
    return True, None # No CAA record founds; return true per RFC8659

def prior_approval_check(flow, root_cert, quick_check=False):
    logging.warning(f"-----------------------------------Entering prior_approval_check()--------------------------------------------------")
    # If refactor this function as a class, can persist the 'row' value below so there's only one SQL query
    host = flow.request.pretty_host
    if approved_hosts:
        logging.info(f'Approved hosts: {approved_hosts}')

    root_fingerprint = root_cert.fingerprint(hashes.SHA256()).hex()
    
    ############ Need to extend this to examine root cert parameters!!!!!!!!!!
    with sqlite3.connect(db_path) as conn:
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

def record_decision(host, decision, root_fingerprint):
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute("REPLACE INTO decisions (host, decision, root, timestamp) VALUES (?, ?, ?, ?)", (host, decision, root_fingerprint, now))
        conn.commit()
    #global approved_hosts
    #if decision == "approved":
        #approved_hosts.add(host)
        #logging.info(f'Approved hosts after adding from user decision: {approved_hosts}')

def is_navigation_request(flow, referer_header, accept_header):
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

def sct_check(flow, root):
    logging.warning(f"-----------------------------------Entering sct_check()--------------------------------------------------")
    cert   = cert_to_x509(flow.server_conn.certificate_list[0])
    issuer_cert = cert_to_x509(flow.server_conn.certificate_list[1])
    logging.info(f'Input cert: {cert.subject.rfc4514_string()}')
    logging.debug(f'Issuer cert: {issuer_cert.subject.rfc4514_string()}')
    
    # Check for SCTs & extract data
    scts = verify_SCTs.extract_scts(flow, cert, ct_log_map)
    if not scts:
        # TODO: Update code to account for external SCTs (e.g. delivered via OCSP or during TLS negotation).  Until then, this check cannot result in FATAL errors.
        logging.error(f"Cert for {flow.request.pretty_url} missing SCT(s)!")
        violation = '⚠️ Certificate missing <a href=https://certificate.transparency.dev/howctworks/ target="_blank">Signed Certificate Timestamps</a> (SCTs)'
        return ErrorLevel.ERROR, violation
    
    violations = []
    # Print out SCT details for debugging purposes
    for i, sct in enumerate(scts, 1):
        logging.debug(f"\nSCT #{i}:")
        for k, v in sct.items():
            logging.debug(f"  {k}: {v}")
        
        # Validate SCT digital signatures (if enabled)
        if verify_signatures:
            validated = verify_SCTs.validate_signature(cert, issuer_cert, sct, i)
            if not validated:
                violations.append(f'⛔ Digital signature validation for <a href=https://certificate.transparency.dev/howctworks/ target="_blank">SCT</a> #{i} failed!')

    # Make call to SSLMate to check for cert/precert inclusion in Certificate Transparency log(s)
    found, revoked = verify_SCTs.check_ctlog_inclusion(flow, cert)
    if found:
        logging.info(f'Publication in Certificate Transparency log confirmed.')
    else:
        not_before = cert.not_valid_before_utc
        logging.info(f'Leaf cert not_valid_before date (UTC): {not_before}')
        now = datetime.now(timezone.utc)
        if now - timedelta(hours=24) < not_before <= now:
            # TODO - Because I'm relying on SSLMate for CRL/OCSP verification at the moment, certs not published to CT logs won't be checked for revocation...
            logging.info('Cert is within Maximum Merge Delay (MMD) window for publishing to Certificate Transparency log.')
            return ErrorLevel.INFO, f'<span style="color: blue;">&nbsp🛈</span>&nbsp&nbspCert not found in CT logs, but within 24hr <a href=https://datatracker.ietf.org/doc/html/rfc6962#section-3 target="_blank">Maximum Merge Delay</a> period.'
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

#====================================================================== Main control logic===================================================================

BYPASS_PARAM = "CertGuard-Token"
approved_hosts = set()
pending_requests = {}

root_store = get_root_store()

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

    logging.info('===================================BEGIN New Cert Verification============================================')
    is_main_page = is_navigation_request(flow, referer_header, accept_header)
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
    logging.debug(f'Trustchain provided by the server: {cert_chain}')

    leaf_cert = cert_chain[0]
    logging.debug(f'The leaf cert is: {leaf_cert.cn} =-.')
    logging.debug(f' ---> The SubAltName(s) are {leaf_cert.altnames}')

    # Retrieve validated root cert as cryptography.hazmat.bindings._rust.x509.Certificate object.
    root_cert, claimed_root = get_root_cert(cert_chain, root_store)
    if root_cert:
        logging.warning(f'Successfully retreived CA Root:  {root_cert.subject.rfc4514_string()}')
        root_hash = (root_cert.fingerprint(hashes.SHA256())).hex()
    else:
        logging.fatal(f'FATAL: Could not validate trust anchor root ({claimed_root}) for cert chain!')
        violation = f'⛔ Could not validate cert against claimed root of:<br>&nbsp&nbsp&nbsp&nbsp<b>{claimed_root}</b>'
        error_screen(flow, None, PAGE_COLOR[ErrorLevel.CRIT], [violation], ErrorLevel.CRIT.value)
        return
    
    # Check to see if hostname is already approved in the database.
    prior_approval = prior_approval_check(flow, root_cert, quick_check=True)
    if prior_approval:
        logging.info(f"User has previously approved {host}.")
        approved_hosts.add(host)  # In-memory cache for improvement performance
        return
    else:
        logging.info(f'Host {flow.request.pretty_host} not found to be previously approved; continuing checks.')

    # Detect approval token from client request
    if token_mode == "get":
        token = flow.request.query.get(BYPASS_PARAM)
        logging.info(f"Detected token in request:       {token}.")
    elif token_mode == "post":
        token = flow.request.urlencoded_form.get(BYPASS_PARAM)
        logging.info(f"Detected token in request:       {token}.")
    elif token_mode == "header":
        token = flow.request.headers.get(f"X-{BYPASS_PARAM}")
        logging.info(f"Detected token in request:       {token}.")

    if token and token in pending_requests:
        orig_req = pending_requests.pop(token)
        if token_mode == "header":
            if intercept_mode == "strict":                       
                # Best effort to replay original request; works for simple HTML form POST requests that return 302 or HTML.
                flow.request.method = orig_req["method"]
                flow.request.path = orig_req["path"]
                flow.request.headers.clear()
                flow.request.headers.update(orig_req["headers"])
                flow.request.content = orig_req["body"]
            else:
                # Synthetic response to close POST request; JavaScript handles page refresh.
                flow.response = http.Response.make(200, f"CertGuard: '{host}' added as approved host via token {token}.", {"Content-Type": "text/plain"})
        elif token_mode == "post":
            flow.request.method = orig_req["method"]
            flow.request.path = orig_req["path"]
            flow.request.content = orig_req["body"]
        elif token_mode == "get":
            flow.request.query.pop(BYPASS_PARAM, None)              # Remove CertGuard parameter before redirect.
            flow.response = http.Response.make(302, b"", {"Location": flow.request.url})

        logging.warning(f"User has accepted warnings for {host} via token: {token}.  Decision will be persisted to database & cached for this session.")
        record_decision(host, "approved", root_hash)
        approved_hosts.add(host)
        return

    if intercept_mode == "compatible":
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

    my_checks = [root_country_check, controlled_CA_checks, example_check, verify_cert_caa, prior_approval_check, sct_check]  # 
    violations=[]
    for check in my_checks:
        error, violation = check(flow, root_cert)
        if error.value > highest_error_level:
            highest_error_level = error.value
            blockpage_color = PAGE_COLOR[error]
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
    