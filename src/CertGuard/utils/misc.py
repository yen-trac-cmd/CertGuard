import inspect
from cryptography.x509 import oid
from cryptography.hazmat.primitives import hashes

def func_name() -> str:
    return inspect.currentframe().f_back.f_code.co_name

def get_ede_description(code: int) -> str:
    """Returns a descriptive string for Extended DNS Error (EDE) codes defined in RFC 8914 and IANA assignments.

    Args:
        code (int): The Extended DNS Error (EDE) code to get the description for.

    Returns:
        str: The descriptive string for the given EDE code.
    """
    EDE_CODES_MAP = {
        0: "Other/unspecified error",
        1: "Unsupported DNSKEY Algorithm",
        2: "Unsupported DS Digest Type",
        3: "Stale DNSSEC Answer",
        4: "Forged DNSSEC Answer",
        5: "DNSSEC Indeterminate Error",
        6: "Invalid signature ('DNSSEC Bogus')",
        7: "DNSSEC Signature Expired",
        8: "DNSSEC Signature Not Yet Valid",
        9: "DNSSEC DNSKEY Missing",
        10: "DNSSEC RRSIGs Missing",
        11: "No Zone Key Bit Set",
        12: "NSEC Missing",
        13: "Resolver returned SERVFAIL RCODE from cache",
        14: "DNS Server Not Ready",
        15: "Domain blocklisted by DNS server operator",
        16: "Domain Censored",
        17: "Domain Filtered (as requested by client)",
        18: "Request Prohibited (client unauthorized)",
        19: "Stale NXDOMAIN Answer",
        20: "Authoritative Nameserver(s) unreachable",
        21: "Requested operation or query not supported",
        22: "No Reachable Authority",
        23: "Network Error",
        24: "Invalid Data",
    }
    return EDE_CODES_MAP.get(code, "Unknown EDE Code")

def get_ocsp_oid_name(oid_dotted: str) -> str:
    """
    Get a human-readable name for common OCSP extension OIDs.
    
    Args:
        oid_dotted: OID in dotted string format
        
    Returns:
        str: Human-readable name or 'unknown'
    """
    oid_names = {
        '1.3.6.1.5.5.7.48.1.2': 'Nonce',
        '1.3.6.1.5.5.7.48.1.3': 'CRL References',
        '1.3.6.1.5.5.7.48.1.6': 'Archive Cutoff',
        '1.3.6.1.5.5.7.48.1.7': 'Service Locator',
        '1.3.6.1.4.1.311.21.4': 'CRL Next Publish',  # Microsoft proprietary https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/69c1c13a-e270-49ad-9bc1-a94fe019c8c9
        # CRL Entry Extensions that can appear in SingleResponse
        '2.5.29.21': 'CRL Reason',
        '2.5.29.23': 'Hold Instruction Code',
        '2.5.29.24': 'Invalidity Date',
        '2.5.29.29': 'Certificate Issuer',
    }
    return oid_names.get(oid_dotted, 'unknown')

def get_hash_algorithm_from_oid(sig_oid):
    """Map signature algorithm OID to hash algorithm"""
    # Common signature algorithm OIDs
    oid_to_hash = {
        # RSA with SHA-256
        oid.SignatureAlgorithmOID.RSA_WITH_SHA256: hashes.SHA256(),
        # RSA with SHA-384
        oid.SignatureAlgorithmOID.RSA_WITH_SHA384: hashes.SHA384(),
        # RSA with SHA-512
        oid.SignatureAlgorithmOID.RSA_WITH_SHA512: hashes.SHA512(),
        # RSA with SHA-1 (deprecated but still used)
        oid.SignatureAlgorithmOID.RSA_WITH_SHA1: hashes.SHA1(),
        # ECDSA with SHA-256
        oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256: hashes.SHA256(),
        # ECDSA with SHA-384
        oid.SignatureAlgorithmOID.ECDSA_WITH_SHA384: hashes.SHA384(),
        # ECDSA with SHA-512
        oid.SignatureAlgorithmOID.ECDSA_WITH_SHA512: hashes.SHA512(),
        # DSA with SHA-256
        oid.SignatureAlgorithmOID.DSA_WITH_SHA256: hashes.SHA256(),
    }
    
    return oid_to_hash.get(sig_oid)