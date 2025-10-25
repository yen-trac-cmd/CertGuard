import dns.resolver
import json
import ipaddress
import logging
import sys
import tomllib
from collections import deque
from enum import Enum
from requests_cache import CachedSession, timedelta


class ErrorLevel(Enum):
    NONE   = 0
    INFO   = 1
    NOTICE = 2
    WARN   = 3
    ERROR  = 4
    CRIT   = 5
    FATAL  = 6

    @property
    def color(self):
        match self:
            case self.INFO:
                return 'Green'
            case self.NOTICE:
                return 'Blue'
            case self.WARN:
                return 'Yellow'
            case self.ERROR:
                return 'Orange'
            case self.CRIT:
                return 'Red'
            case self.FATAL:
                return 'Maroon'

class Config:
    def __init__(self) -> None:
        with open("config.toml", "rb") as f:
            cfg = tomllib.load(f)

        self.logging_level     = cfg["general"]["logging_level"].lower()             # "debug", "info", "warn", "error", or "alert"
        self.user_resolvers    = cfg["general"]["resolvers"]
        self.dns_timeout       = cfg["general"]["dns_timeout"]
        self.db_path           = cfg["general"]["db_path"]
        self.intercept_mode    = cfg["general"]["intercept_mode"].lower()            # "compatible" or "strict"
        self.token_mode        = cfg["general"]["token_mode"].lower()                # "header", "get", or "post"
        self.exempt_eTLDs      = cfg["caa_exceptions"]["exempt_eTLDs"]
        self.filtering_mode    = cfg["country_filtering"]["filtering_mode"].lower()  # "allow" or "warn"
        self.restricted_roots  = cfg["controlled_roots"]["restricted_roots"]
        self.revocation_checks = cfg["tls_config"]["revocation_checks"]
        self.prohibited_roots  = cfg["controlled_roots"]["prohibited_roots"]
        self.quick_check       = cfg["sct_config"]["quick_check"]
        self.verify_signatures = cfg["sct_config"]["verify_signatures"]
        self.verify_inclusion  = cfg["sct_config"]["verify_inclusion"]
        self.country_list      = [country.upper() for country in cfg["country_filtering"]["country_list"]]
        self.blocklist         = [country.upper() for country in cfg["country_filtering"]["blocklist"]]

        # Optional params
        self.custom_roots_dir = cfg["general"].get("custom_roots_dir", None)
        self.min_tls_version  = cfg.get("tls_config", {}).get("min_tls_version", 1.2)
        ciphersuite_val = cfg.get("tls_config", {}).get("ciphersuites", None)
        self.ciphersuites = ciphersuite_val.upper() if ciphersuite_val is not None else None

        # ISO country map
        with open('./resources/iso-3166-alpha2_list.json') as iso_countries:
            self.iso_country_map = json.load(iso_countries)

        # Validate user-supplied config values
        if type(self.dns_timeout) != float:
            logging.fatal(f"dns_timeout in config.toml must be configured as floating point value!")

        if self.filtering_mode not in ['allow', 'warn']:
            logging.fatal(f"Invalid country filtering mode defined in config.toml!")

        if self.intercept_mode not in ['compatible', 'strict']:
            logging.fatal(f"Invalid 'intercept_mode' defined in config.toml!")

        if self.token_mode not in ['header', 'post', 'get']:
            logging.fatal(f"Invalid 'token_mode' defined in config.toml!")

        for entries in [self.country_list, self.blocklist]:
            if not all(isinstance(country, str) and len(country) == 2 for country in entries):
                raise AssertionError("All countries in config.toml must be specified as 2-character iso-3166-alpha2 codes!")
            unrecognized = [entry for entry in entries if entry not in self.iso_country_map]
            assert not unrecognized, f"Unrecognized country specified in config.toml: {unrecognized}!"
        
        # DNS resolver setup
        self.resolver = dns.resolver.Resolver()
        for ip in self.user_resolvers:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                logging.fatal(f"Invalid DNS resolver entry in config.toml: {ip}")
        self.resolvers = deque(self.user_resolvers)

        # Load Public Suffix List
        PSL_URL = 'https://publicsuffix.org/list/public_suffix_list.dat'
        self.public_suffix_list = []

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
                logging.fatal(f'Cannot load Public Suffix List from network or local cache; failing closed.')
                logging.fatal(f'Check network connectivity and site availability to {PSL_URL}')
                sys.exit()

        if psl_response.from_cache:
            logging.debug('Public Suffix List retreived from cache.')

        for line in psl_response.text.splitlines():
            if not line.strip().startswith('//') and line.strip():
                self.public_suffix_list.append(line.strip())
        
        #recombined = "\n".join(self.public_suffix_list)
        #with open('psl_list.txt', 'w') as f:
        #    f.write(recombined)
            