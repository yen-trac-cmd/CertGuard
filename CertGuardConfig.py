from collections import deque
from enum import Enum
import dns.resolver
import json
import ipaddress
import logging                          # Valid levels = debug, info, warning, error, critical, fatal.  
import sys
import tomllib

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
        self.prohibited_roots  = cfg["controlled_roots"]["prohibited_roots"]
        self.verify_signatures = cfg["sct_config"]["verify_signatures"]
        self.country_list      = [country.upper() for country in cfg["country_filtering"]["country_list"]]
        self.blocklist         = [country.upper() for country in cfg["country_filtering"]["blocklist"]]

        # Optional params
        self.custom_roots_dir = cfg["general"].get("custom_roots_dir", None)
        self.min_tls_version  = cfg.get("tls_config", {}).get("min_tls_version", 1.2)
        ciphersuite_val = cfg.get("tls_config", {}).get("ciphersuites", None)
        self.ciphersuites = ciphersuite_val.upper() if ciphersuite_val is not None else None

        # ISO country map
        with open('iso-3166-alpha2_list.json') as iso_countries:
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

        # Public Suffix List
        # TODO: Add a check to fetch new 'public_suffix_list.dat' from https://publicsuffix.org/list/public_suffix_list.dat 
        # if local copy is >5 days old.  Can reuse code from verify_SCTs.load_ct_log_list()
        self.public_suffix_list = []
        try:
            with open('public_suffix_list.dat', 'r', encoding='utf-8') as psl:
                for line in psl:
                    if not line.strip().startswith('//') and line.strip():
                        self.public_suffix_list.append(line.strip())
        except FileNotFoundError:
            logging.info(f"Error: Cannot locate public_suffix_list.dat in the current directory!")

            