from collections import deque
import dns.resolver
import json
import ipaddress
import logging                          # Valid levels = debug, info, warning, error, critical, fatal.  
import sys
import tomllib

class CertGuardConfig:
    def __init__(self) -> None:
        with open("config.toml", "rb") as f:
            cfg = tomllib.load(f)

        self.logging_level     = cfg["general"]["logging_level"].lower()
        self.user_resolvers    = cfg["general"]["resolvers"]
        self.dns_timeout       = cfg["general"]["dns_timeout"]
        self.db_path           = cfg["general"]["db_path"]
        self.intercept_mode    = cfg["general"]["intercept_mode"].lower()
        self.token_mode        = cfg["general"]["token_mode"].lower()
        self.exempt_eTLDs      = cfg["caa_exceptions"]["exempt_eTLDs"]
        self.filtering_mode    = cfg["country_filtering"]["filtering_mode"].lower()
        self.restricted_roots  = cfg["controlled_roots"]["restricted_roots"]
        self.prohibited_roots  = cfg["controlled_roots"]["prohibited_roots"]
        self.verify_signatures = cfg["sct_config"]["verify_signatures"]
        self.country_list      = [country.upper() for country in cfg["country_filtering"]["country_list"]]
        self.blocklist         = [country.upper() for country in cfg["country_filtering"]["blocklist"]]

        # Optional params
        try:
            self.custom_roots_dir = cfg["general"]["custom_roots_dir"]
        except Exception:
            self.custom_roots_dir = None
        try:
            self.min_tls_version  = cfg["tls_config"]["min_tls_version"]
        except Exception:
            self.min_tls_version  = 1.2
        try:
            self.ciphersuites     = cfg["tls_config"]["ciphersuites"].upper()
        except Exception:
            self.ciphersuites     = None

        # DNS resolver setup
        self.resolver = dns.resolver.Resolver()
        for ip in self.user_resolvers:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                logging.fatal(f"Invalid DNS resolver entry in config.toml: {ip}")
        self.resolvers = deque(self.user_resolvers)

        # ISO country map
        with open('iso-3166-alpha2_list.json') as iso_countries:
            self.iso_country_map = json.load(iso_countries)

        # Public Suffix List
        # TODO: Add a check to fetch new 'public_suffix_list.dat' from https://publicsuffix.org/list/public_suffix_list.dat if local copy is >5 days old.
        # Can reuse code from verify_SCTs.load_ct_log_list()
        self.public_suffix_list = []
        try:
            with open('public_suffix_list.dat', 'r', encoding='utf-8') as psl:
                for line in psl:
                    if not line.strip().startswith('//') and line.strip():
                        self.public_suffix_list.append(line.strip())
        except FileNotFoundError:
            logging.error(f"FATAL Error: Cannot locate public_suffix_list.dat in the current directory!")
            sys.exit()
