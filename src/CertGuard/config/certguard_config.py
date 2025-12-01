import dns.resolver
import ipaddress
import json
import logging
import tomllib
from collections import deque
from dataclasses import dataclass
from enum import Enum, IntEnum
from logging.handlers import RotatingFileHandler

BYPASS_PARAM = "CertGuard-Token"

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

class DisplayLevel(IntEnum):
    TOPLEVEL = -2
    CRITICAL = -1     # Critical errors that cannot be bypassed
    WARNING  = 0      # Warnings that trigger CertGuard's blockpage
    POSITIVE = 1      # Noteworthy positive finding
    VERBOSE  = 2      # Informational findings

@dataclass
class Finding:
    level: DisplayLevel
    check: str
    message: str

class Config:
    def __init__(self) -> None:
        with open("config.toml", "rb") as f:
            cfg = tomllib.load(f)

        self.logging_level     = cfg["general"]["console_logging_level"].lower()             # "debug", "info", "warn", "error", or "alert"
        self.user_resolvers    = cfg["general"]["resolvers"]
        self.dns_timeout       = cfg["general"]["dns_timeout"]
        self.db_path           = cfg["general"]["db_path"]
        self.intercept_mode    = cfg["general"]["intercept_mode"].lower()            # "compatible" or "strict"
        self.token_mode        = cfg["general"]["token_mode"].lower()                # "header", "get", or "post"
        self.exempt_eTLDs      = cfg["caa_exceptions"]["exempt_eTLDs"]
        self.filtering_mode    = cfg["country_filtering"]["filtering_mode"].lower()  # "allow" or "warn"
        self.restricted_roots  = cfg["controlled_roots"]["restricted_roots"]
        self.revocation_checks = cfg["tls_config"]["revocation_checks"]
        self.certguard_checks  = cfg["tls_config"]["bypass_mitmproxy_checks"]
        self.prohibited_roots  = cfg["controlled_roots"]["prohibited_roots"]
        self.quick_check       = cfg["sct_config"]["quick_check"]
        self.verify_signatures = cfg["sct_config"]["verify_signatures"]
        self.verify_inclusion  = cfg["sct_config"]["verify_inclusion"]
        self.enforce_dane      = cfg["dane_config"]["enforce_dane"]
        self.require_dnssec    = cfg["dane_config"]["require_dnssec"]
        self.country_list      = [country.upper() for country in cfg["country_filtering"]["country_list"]]
        self.blocklist         = [country.upper() for country in cfg["country_filtering"]["blocklist"]]

        # Optional params
        self.custom_roots_dir  = cfg["general"].get("custom_roots_dir", None)
        self.bp_verbosity      = cfg["general"].get("blockpage_verbosity", 0)        
        self.min_tls_version   = cfg.get("tls_config", {}).get("min_tls_version", 1.2)
        ciphersuite_val        = cfg.get("tls_config", {}).get("ciphersuites", None)
        self.ciphersuites      = ciphersuite_val.upper() if ciphersuite_val is not None else None

        # ISO country map
        with open('./resources/iso-3166-alpha2_list.json') as iso_countries:
            self.iso_country_map = json.load(iso_countries)

        # Validate user-supplied config values
        if type(self.dns_timeout) != float:
            logging.critical(f"dns_timeout in config.toml must be configured as floating point value!")

        if self.filtering_mode not in ['allow', 'warn']:
            logging.facriticaltal(f"Invalid country filtering mode defined in config.toml!")

        if self.intercept_mode not in ['compatible', 'strict']:
            logging.critical(f"Invalid 'intercept_mode' defined in config.toml!")

        if self.token_mode not in ['header', 'post', 'get']:
            logging.critical(f"Invalid 'token_mode' defined in config.toml!")

        for entries in [self.country_list, self.blocklist]:
            if not all(isinstance(country, str) and len(country) == 2 for country in entries):
                raise AssertionError("All countries in config.toml must be specified as 2-character iso-3166-alpha2 codes!")
            unrecognized = [entry for entry in entries if entry not in self.iso_country_map]
            assert not unrecognized, f"Unrecognized country specified in config.toml: {unrecognized}!"
        
        if self.bp_verbosity not in [0,1,2]:
            raise AssertionError("The 'blockpage_verbosity' setting in config.toml only supports integer values between 0-2.  Please correct.")

        # DNS resolver setup
        self.resolver = dns.resolver.Resolver()
        for ip in self.user_resolvers:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                logging.critical(f"Invalid DNS resolver entry in config.toml: {ip}")
        self.resolvers = deque(self.user_resolvers)

        #recombined = "\n".join(self.public_suffix_list)
        #with open('psl_list.txt', 'w') as f:
        #    f.write(recombined)

class Logger:
    from __init__ import __version__
    _logger = None
    log_file = "logs/logfile.log"

    @classmethod
    def get_logger(self):
        if self._logger:
            return self._logger
        
        with open(self.log_file, 'a') as f:
            f.write(f'\n===============================================\n{{\n"CertGuard_version": "{self.__version__}",\n"site_visits": [\n')

        log_format = '{"Timestamp": "%(asctime)s.%(msecs)03d", %(message)s},'
        date_format = '%Y-%m-%dT%H:%M:%S'

        formatter = logging.Formatter(log_format, datefmt=date_format)
        file_handler = RotatingFileHandler(self.log_file, maxBytes=5*1048576, backupCount=7)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)

        log = logging.getLogger("CertGuard")
        log.setLevel(logging.DEBUG)

        if not any(
            isinstance(h, logging.FileHandler)
            and getattr(h, "baseFilename", None) == file_handler.baseFilename
            for h in log.handlers
        ):
            log.addHandler(file_handler)

        log.propagate = False
        logging.info(f"Logging to {self.log_file}.")
        self._logger = log
        return log
