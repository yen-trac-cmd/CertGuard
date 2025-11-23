import logging
from dns.rdtypes.ANY import CAA
from dns.resolver import dns
from helper_functions import load_public_suffix_list

# Populate Public Suffix List from pre-loaded file
public_suffix_list = load_public_suffix_list()


def check_caa_per_domain(config, domain: str, ca_identifiers: list[str]) -> tuple[bool, str | None, bool]:
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
    logging.warning("-----------------------------------Entering check_caa_per_domain()--------------------------------")
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
        logging.warning(f" Checking for DNS CAA records published at '{check_domain}' against enumerated CA identifiers: {ca_identifiers}")
        
        # Check to see if comparing against an "effective TLD" / public suffix, with exceptions as defined in config.toml.
        # See https://developer.mozilla.org/en-US/docs/Glossary/eTLD and https://publicsuffix.org/ for reference
        
        #if check_domain in config.public_suffix_list and not check_domain in CONFIG.exempt_eTLDs: etld = True 
        if check_domain in public_suffix_list and not check_domain in config.exempt_eTLDs: etld = True 

        try:
            current_resolver = config.resolvers[0]
            logging.debug(f'   Using resolver: {current_resolver}')

            query = dns.message.make_query(check_domain, dns.rdatatype.CAA, want_dnssec=True)
            got_response=False
            attempt = 0
            while got_response==False:
                try:
                    answers = dns.query.udp_with_fallback(query, current_resolver, timeout=config.dns_timeout)  # timeout parameter is required, otherwise mitmproxy can freeze
                    got_response=True
                except dns.exception.Timeout:
                    config.resolvers.rotate(1)
                    current_resolver = config.resolvers[0]
                    logging.error(f'DNS query using resolver {config.resolvers[-1]} for "{check_domain}" timed out!!  ...Trying again with resolver {current_resolver}.')
                except Exception as e:
                    if attempt == 3:
                        break
                    config.resolvers.rotate(1)
                    current_resolver = config.resolvers[0]
                    logging.debug(f"Exception encountered for DNS query using resolver {config.resolvers[-1]}: {e}")
                    logging.error(f'  --> Trying again with resolver {current_resolver}.')
                    attempt += 1

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
                        logging.debug(f' Skipping checks against malformed or non-CAA record: {rrset}')
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
                                    return True, f'&emsp;&emsp;▶ Matching CAA record (<code>{ca}</code>) <em>only</em> found at <b>.{check_domain}</b> eTLD!', records_found
                                logging.warning(f"SUCCESS: CA from mapping ({ca}) matched CAA record published at {check_domain}.")
                                return True, None, records_found

        else:  # No answer rdata retrieved from CAA query
            logging.info(f'No published CAA record found at {check_domain}.')
            continue
    
    # Exhausted CAA record search for DNS tree.  If CAA records found, but no matches for Issuing CA of leaf certificate, return warning.
    if is_wildcard and issuewild_properties:
        logging.error(f"Published 'issuewild' CAA records do not authorize Issuing CA of wildcard leaf cert!")
        return False, f"&emsp;&emsp;▶ Wildcard CAA records do not authorize CA for wildcard site certificate.", records_found
    
    if issue_properties:
        logging.error(f"Published 'issue' CAA records do not authorize Issuing CA for leaf cert!")
        return False, f"&emsp;&emsp;▶ CAA records do not authorize CA for site certificate.", records_found

    # No CAA records found at all
    logging.warning(f'No published CAA record found; return true per RFC8659')
    return True, None, records_found # No CAA record founds; return true per RFC8659