import inspect

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