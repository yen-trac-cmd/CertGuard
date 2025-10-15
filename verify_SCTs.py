import base64
import datetime
import hashlib
import logging  
import os
import requests
import sys
import time
import urllib.parse
from requests_cache import CachedSession
from helper_functions import get_cert_domains
from cryptography import x509, exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import  Encoding, PublicFormat, load_der_public_key
from cryptography.x509.oid import ExtensionOID
from datetime import timedelta
from enum import IntEnum
from mitmproxy import http
from typing import Optional, Tuple

# Fetch SSLMate API key from environment variable.  TODO: Migrate to proper key vault.
try:
    SSLMATE_KEY = os.environ["SSLMATE_KEY"]
except:
    logging.fatal("Please define the 'SSLMATE_KEY' environment variable with your API key from SSLMate.com.")

SSLMATE_QUERY_URL = "https://api.certspotter.com/v1/issuances"
CT_LOG_LIST_URL   = "https://www.gstatic.com/ct/log_list/v3/log_list.json"     # Google's CT Log list

class RevocationReason(IntEnum):
    def __new__(cls, value: int, description: str):
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.description = description
        return obj

    unspecified         = (0,  "Unspecified reason")
    keyCompromise       = (1,  "Key material has been compromised")
    cACompromise        = (2,  "Certificate Authority compromise")
    affiliationChanged  = (3,  "Subject's affiliation has changed")
    superseded          = (4,  "Certificate has been superseded")
    cessationOfOperation= (5,  "Certificate no longer needed (operation ceased)")
    certificateHold     = (6,  "Certificate placed on hold")
    removeFromCRL       = (8,  "Certificate removed from CRL")
    privilegeWithdrawn  = (9,  "Privilege withdrawn")
    aACompromise        = (10, "Attribute Authority compromise")
    unknown             = (-1, "Unknown or unrecognized reason")

    @classmethod
    def _missing_(cls, value: int):
        return cls.unknown

def load_ct_log_list() -> dict:
    """
    Loads Google's well-known CT log list and transforms it into a dictionary of CT log entry metadata, keyed by log_id_bytes.
    """
    
    session = CachedSession('./resources/ct_log_list.json', expire_after=timedelta(hours=24), backend="filesystem", stale_if_error=True, allowable_codes=[200])
    logging.info(f'Session cache contains {CT_LOG_LIST_URL}? {session.cache.contains(url=CT_LOG_LIST_URL)}')
    try:
        ct_log_list = session.get(CT_LOG_LIST_URL)
        #ct_log_list = session.get('https://www.gstatic.com/ct/log_list/v3/log_list.jsonx')   # Bogus URL for fault testing
        ct_log_list.raise_for_status()
        if not ct_log_list.from_cache:
            logging.info(f"Fresh Certificate Transparency Log List downloaded from {CT_LOG_LIST_URL}, Status Code: {ct_log_list.status_code}")

    except Exception as e:
        logging.warning(f"Error encountered during fetch: {e}")
        logging.warning(f"...falling back to cached content. Check connectivity and site availability.")
        ct_log_list = session.get(CT_LOG_LIST_URL, only_if_cached=True)
        if ct_log_list.status_code != 200:
            logging.fatal(f'Cannot load Certificate Transparency Log List from network or local cache; failing closed.')
            logging.fatal(f'Check network connectivity and site availability to {CT_LOG_LIST_URL}')
            sys.exit()

    if ct_log_list.from_cache:
        logging.debug('Certificate Transparency log list retreived from cache.')

    log_list = ct_log_list.json()

    # Transform log_list mapping
    mapping = {}
    for operator in log_list.get("operators", []):
        for entry in operator.get("logs", []):
            key_b64 = entry.get("key")
            log_id_b64 = entry.get("log_id")
            if not key_b64 or not log_id_b64:
                continue

            try:
                # Remove whitespace/linebreaks and extend 'entry' to include log operator name and public key in DER format.
                key_b64 = "".join(key_b64.split())
                log_id_b64 = "".join(log_id_b64.split())

                pubkey_der = base64.b64decode(key_b64)
                log_id_bytes = base64.b64decode(log_id_b64)

                pubkey = serialization.load_der_public_key(pubkey_der, backend=default_backend())
                entry["pubkey"] = pubkey
                entry["operator_name"] = operator.get("name")

                # Return 'mapping' dictionary, keyed by the base64-decoded bytes of the original 'log_id' value for the CT Log.
                mapping[log_id_bytes] = entry

            except Exception as e:
                logging.error(f"Failed to load log public key; exception: {e}")
                continue

    return mapping

def parse_ct_extensions(ext_bytes: bytes) -> dict:
    """
    Parse Static CT API-style SCT extensions into a dictionary.
   
    Args:
        ext_bytes (bytes): The extracted extension bytes from a Signed Certificate Timestamp (SCT)

    Returns:
        dict: A 1-item dictionary with one of three possible keys:
            'leaf_index': The index of a leaf certificate in CT Log server implementing the Static Certificate Transparency API (fomerly known as 'Sunlight')
            'leaf_index_error': The (non-compliant) number of bytes parsed for a type-0 (lef_index) SCT extension (Any byte length other than 5 is invalid)
            'Unknown SCT extension type x': Provides hex listing of data bytes for unknown extension types, where 'x' is the extension type number.
    
    Each extension is encoded as:
        1 byte  - extension_type
        2 bytes - length (big-endian)
        N bytes - extension_data
    """
    parsed = {}
    offset = 0
    total_length = len(ext_bytes)

    while offset < total_length:
        # --- Parse header ---
        remaining = total_length - offset
        if remaining < 3:
            # Not enough bytes left for a valid header
            break

        extension_type = ext_bytes[offset]
        extension_length = int.from_bytes(ext_bytes[offset + 1:offset + 3], "big")
        offset += 3  # move past header

        # --- Extract data ---
        if offset + extension_length > total_length:
            # Prevent buffer overrun if malformed
            break

        extension_data = ext_bytes[offset:offset + extension_length]
        offset += extension_length

        # --- Handle known extension types ---
        if extension_type == 0:  # leaf_index
            if len(extension_data) == 5:
                parsed["leaf_index"] = int.from_bytes(extension_data, "big")
            else:
                parsed["leaf_index_error"] = f"Unexpected length: {len(extension_data)} bytes"
        else:
            parsed[f"Unknown SCT extension type {extension_type}"] = extension_data.hex()

    return parsed

def extract_scts(flow: http.HTTPFlow, cert: x509.Certificate, ct_log_map) -> list[dict]:
    logging.warning(f"-----------------------------------Entering extract_scts()--------------------------------------------------")
    # LIMITATION: The code only extracts SCTs embedded inside X.509 certs. Additional extraction logic is 
    # necessary to account for SCTs delivered via OCSP stapling or TLS extension during session negotiation.  

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
    except x509.ExtensionNotFound:
        logging.info("No SCT extension found in certificate.")
        return []

    scts = ext.value  # iterable of SCT objects

    for count, sct in enumerate(scts):
        #logging.info(f"SCT log_id {count} (hex): {sct.log_id.hex()}")
        logging.info(f"SCT log_id {count} (b64): {base64.b64encode(sct.log_id).decode()}")

    if ct_log_map == None:
        error = f"<html><head><title>Error!</title></head><body>Could not load Certificate Transparency log file from {CT_LOG_LIST_URL}!"
        flow.repsonse = http.Response.make(500, error, {"Content-Type": "text/html"})

    sct_data = []
    for sct in scts:
        ct_log_entry = ct_log_map.get(sct.log_id)
        parsed_exts = parse_ct_extensions(sct.extension_bytes)

        sct_data.append({
            "version": sct.version.name,
            "log_id_hex": sct.log_id.hex(),
            "log_id_b64": base64.b64encode(sct.log_id).decode(),
            "timestamp": sct.timestamp,
            "timestamp_unix": int(sct.timestamp.timestamp()*1000),
            "entry_type": sct.entry_type.name,
            "hash_algorithm": sct.signature_hash_algorithm.name,
            "signature_algorithm": sct.signature_algorithm.name,
            "signature": sct.signature.hex(),
            "extension_bytes": sct.extension_bytes.hex(),
            **parsed_exts, # include leaf_index for static CT API and/or other parsed extensions, if present.
            "ct_log_description": ct_log_entry.get("description") if ct_log_entry else None,
            "ct_log_operator": ct_log_entry.get("operator_name") if ct_log_entry else None,
            "ct_log_key": ct_log_entry.get("key") if ct_log_entry else None,
            "ct_log_url": ct_log_entry.get("url") if ct_log_entry else None,
            "ct_log_mmd": ct_log_entry.get("mmd") if ct_log_entry else None,
            "ct_log_state": ct_log_entry.get("state") if ct_log_entry else None,
            "ct_log_temporal_interval": ct_log_entry.get("temporal_interval") if ct_log_entry else None,
        })
    return sct_data

def validate_signature(cert: x509.Certificate, issuer_cert: x509.Certificate, sct: dict) -> tuple[bool, bytes | None]:
    """
    Validate ECDSA digital signature on a Signed Certificate Timestamp (SCT)
    Code adapted from https://research.ivision.com/how-does-certificate-transparency-work.html.
    
    Args:
        cert (x509.Certificate): The cert from which to extract 
        issuer_cert (x509.Certificate): The Issuing CA cert whose public key hash will be included as part of the signed SCT data structure
        sct (dict): A dictionary containing the timestamp and signature bytes from a SCT, along with the corresponding CT log server's public ECDSA key

    Returns:
        bool:  True/False result indicating if the digital signature was verified (or not)
        bytes: The 'sct_data' structure that forms the basis of the Merkle tree leaf and SCT signature.
        None:  Returned if validation fails for any reason
    """
    #TODO Add support for PKCS#1 v1.5 signatures
    timestamp = bytes.fromhex(hex(round(sct["timestamp"].replace(tzinfo=datetime.timezone.utc).timestamp() * 1000))[2:].zfill(16))
    issuer_public_key_hash = hashlib.sha256(issuer_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).digest()
    sct_extension = bytes.fromhex(sct["extension_bytes"])                          # To support future leaf_index extension by static CT API logs
    ext_length = bytes.fromhex(hex(len(sct_extension))[2:].zfill(4))

    sct_data: bytes = bytes()
    sct_data += b"\0"                                                               # Version: 0=v1
    sct_data += b"\0"                                                               # SignatureType: 0=certificate_timestamp
    sct_data += timestamp                                                           # uint64 timestamp
    sct_data += b"\x00\x01"                                                         # LogEntryType: 0x0001=precert_entry, 0x0000=cert_entry
    sct_data += issuer_public_key_hash                                              # PreCert.opaque: issuer_key_hash[32]
    sct_data += bytes.fromhex(hex(len(cert.tbs_precertificate_bytes))[2:].zfill(6)) # PreCert.TBSCertificate.opaque: 3-byte-length 
    sct_data += cert.tbs_precertificate_bytes                                       # PreCert.TBSCertificate (actual bytes)
    sct_data += ext_length                                                          # CtExtensions: 2-byte-length(extensions)
    sct_data += sct_extension                                                       # CtExtensions; only one type (0) currently defined for leaf_index.
    #logging.debug(f'Data structure to verify SCT signature against: {sct_data.hex()}')

    # Check to ensure CT Log server public key was mapped into CT Log Map
    if sct["ct_log_key"] == None:
        logging.error(f'Could not identify Certificate Transparency log server public key.')
        return False, None
    
    # Loads public key of CT log server
    pubkey = load_der_public_key(base64.b64decode(sct["ct_log_key"]))
        
    try:
        # Validates SCT signature against sct_data structure constructed above
        pubkey.verify(bytes.fromhex(sct["signature"]), sct_data, ec.ECDSA(hashes.SHA256()))
        return True, sct_data
    except exceptions.InvalidSignature:
        return False, None
        
def ctlog_quick_check(flow: http.HTTPFlow, leaf_cert: x509.Certificate) -> Tuple[bool, bool, Optional[str]]:
    logging.warning(f"-----------------------------------Entering check_ctlog_inclusion()--------------------------------------------------")
    leaf_cert_sha256 = leaf_cert.fingerprint(hashes.SHA256()).hex()
    leaf_precert_tbs_sha256 = hashlib.sha256(leaf_cert.tbs_precertificate_bytes).hexdigest()
    
    logging.info(f'Leaf cert SHA256 fingerprint:   {leaf_cert_sha256}')
    logging.debug(f'  - tbs_precertificate_bytes:   {base64.b64encode(leaf_cert.tbs_precertificate_bytes).decode()}')
    logging.info(f'  - Leaf precert TBS SHA256:    {leaf_precert_tbs_sha256} ')

    # Gets all FQDNs in cert (CN + SANs).  If present in cert, use FQDN from flow object for SSLMate query, otherwise use first FQDN in returned list.
    cert_domains = get_cert_domains(leaf_cert)    
    fqdn = (flow.request.pretty_host).lower()
    if len(cert_domains) == 0:
        logging.error(f'Cannot identify FQDN for which to query SSLMate!')
        return False, False, f'Cannot identify FQDN for which to query SSLMate!'

    if fqdn in cert_domains:
        target_fqdn = fqdn
    else:
        target_fqdn = cert_domains[0]
    
    logging.warning(f'Searching SSLMate for: {target_fqdn}')
    max_retries = 2
    delay = 1
    after = None
    records = False
    all_records = []
    found = False
    revoked = False
    headers = {"Authorization": "Bearer " + SSLMATE_KEY}
    
    while True:
        query = f'{SSLMATE_QUERY_URL}?domain={target_fqdn}&expand=revocation'
        if after is not None:
            query += f'&after={after}'

        for attempt in range(max_retries):
            try:
                resp = requests.get(query, headers=headers)
                resp.raise_for_status()

                records = resp.json()
                all_records.extend(records)
                break

            except requests.exceptions.HTTPError as error:
                logging.error(f'SSLMate query attempt #{attempt+1} failed: {error}.  Retrying in {delay}s...')
                time.sleep(delay)
                delay *=2
            except Exception as e:
                logging.error(f'Unknown error occurred: {e}.  Retrying in {delay}s...')
                time.sleep(delay)
                delay *=2
        
        if records == False:
            logging.error(f'Unable to query SSLMate for {flow.request.pretty_host}; FAILING CLOSED!')
            return found, revoked, f'Error encountered attempting to query SSLMate {e} '  # False, False, error

        # SSLMate truncates responses at 100 records per request, so if less than 100 records are returned it indicates the end of the recordset.
        # ...Otherwise append an "&after=xxxx" query parameter (where xxxx is the last record ID number from the previous recordset) to retrieve the next recordset.
        if len(records) < 100:
            break
        after = records[-1]["id"]
    
    if all_records == []:
        logging.error(f'Empty response from SSLMate for {flow.request.pretty_host}')
        return found, revoked, None  # False, False, None

    logging.info(f'Number of CT log records:       {len(all_records)}')

    for i, entry in enumerate(all_records):
        candidate_cert_hash = entry["cert_sha256"]
        candidate_tbs_hash = entry["tbs_sha256"]
        
        logging.info(f'Cert hash # {i} from CT log:      {candidate_cert_hash}')
        logging.info(f'TBS hash # {i} from CT log:       {candidate_tbs_hash}')

        checks = [
            (candidate_cert_hash, leaf_cert_sha256, "final X.509 cert"),
            (candidate_tbs_hash, leaf_precert_tbs_sha256, "precert TBS"),
        ]

        for candidate, expected, label in checks:
            if candidate == expected:
                logging.info(f"Matching hash for {label} found")
                found = True

                if entry["revoked"]:
                    reason_code = entry["revocation"]["reason"]
                    rev_time = entry["revocation"]["time"]
                    revoked = f"{rev_time}.<br>Revocation reason: <b>{RevocationReason(reason_code).description}</b>."
                break
        if found == True:
            break

    if not found:
        logging.warning(f'Hash for {flow.request.pretty_host} not found in CT log!')

    return found, revoked, None

def verify_inclusion(sct_data: bytes, ct_log_url: str, sct_timestamp: int, log_mmd: int) -> Tuple[bool, Optional[str]]:
    """
    Verify inclusion of a leaf hash using SCT data, accounting for Maximum Merge Delay (MMD).

    Args:
        sct_data (bytes):     The data structure that the CT log server signs to generate SCTs
        ct_log_url (str):     An RFC6962-compliant Certificate Transparency log base URL
        sct_timestamp (int):  The UTC timestamp (in unix epoch miliseconds) recorded in the SCT 
        log_mmd (int):        The MMD, in seconds, for the CT log server (typically 86,400)

    Returns:
        bool: Returns True for successful inclusion verification using retrieved audit proof from the CT log.
    """
    REQUEST_TIMEOUT = 2.5  # seconds
    sth_url = ct_log_url + 'ct/v1/get-sth'
    proof_url_template = ct_log_url + 'ct/v1/get-proof-by-hash?hash={}&tree_size={}'

    #Compute the RFC6962 leaf hash for a MerkleLeaf.  The 0x00 prefix is for timestamped entries (X.509 cert / precert).
    leaf_hash = hashlib.sha256(b"\x00" + sct_data).digest()
    leaf_hash_b64 = base64.b64encode(leaf_hash).decode("utf-8")

    # Fetch latest Signed Tree Head from CT log server
    try:
        logging.debug(f'Attempting to fetch latest STH from: {sth_url}')
        sth_resp = requests.get(sth_url, timeout=REQUEST_TIMEOUT)
        sth_resp.raise_for_status()
    except requests.exceptions.Timeout:
        logging.error("Timeout fetching STH.")
        return False, "Timeout fetching STH."
    except requests.RequestException as e:
        logging.error(f"HTTP error fetching STH: {e}")
        return False, f"HTTP error fetching STH: {e}"

    try:
        sth = sth_resp.json()
    except ValueError:
        logging.error("Failed to decode STH JSON response.")
        return False, "Failed to decode STH JSON response."

    tree_size = sth.get("tree_size")
    sth_root_b64 = sth.get("sha256_root_hash")
    if tree_size is None or sth_root_b64 is None:
        logging.error("STH missing required fields.")
        return False, "STH missing required fields."

    sth_root = base64.b64decode(sth_root_b64)
    logging.info(f" Latest STH: tree_size={tree_size}, root={sth_root_b64}")

    # Fetch Merkle tree inclusion proof
    leaf_hash_enc = urllib.parse.quote(leaf_hash_b64)
    proof_url = proof_url_template.format(leaf_hash_enc, tree_size)
    try:
        logging.debug(f'Attempting to fetch inclusion proof from: {proof_url}')
        proof_resp = requests.get(proof_url, timeout=REQUEST_TIMEOUT)
        if proof_resp.status_code == 404:
            if sct_timestamp + log_mmd >= int(time.time()):
                logging.info("Note: Leaf might not yet be included in the current STH (e.g. within MMD).")
            else:
                logging.error("Leaf missing and past MMD window!")
                return False, "Leaf missing and past MMD window!"
        proof_resp.raise_for_status()
        proof = proof_resp.json()
    except requests.exceptions.Timeout:
        logging.error("Timeout fetching inclusion proof. Try again later.")
        return False, "Timeout fetching inclusion proof. Try again later."
    except requests.RequestException as e:
        logging.error(f"HTTP error fetching inclusion proof: {e}")
        return False, f"HTTP error fetching inclusion proof: {e}"
    except ValueError:
        logging.error("Failed to decode inclusion proof JSON.")
        return False, "Failed to decode inclusion proof JSON."

    # Validate proof fields
    if "leaf_index" not in proof or "audit_path" not in proof:
        logging.error("Proof missing required fields.")
        return False, "Proof missing required fields."

    leaf_index = proof["leaf_index"]
    try:
        audit_path = [base64.b64decode(p) for p in proof["audit_path"]]
    except Exception as e:
        logging.error(f"Failed to decode audit path: {e}")
        return False, f"Failed to decode audit path: {e}"

    # Compute Merkle root and compare against retrieved STH root
    computed_root = compute_merkle_root(leaf_hash, leaf_index, audit_path, tree_size)
    computed_root_b64 = base64.b64encode(computed_root).decode()

    logging.info(f" Leaf index: {leaf_index}, audit_path length: {len(audit_path)}")
    logging.info(f" Computed root: {computed_root_b64}")
    logging.info(f" STH root:      {sth_root_b64}")

    match = computed_root == sth_root
    if not match:
        logging.error('Could not verify cert inclusion from audit proof; computed tree head hash mismatch.')
        return match, f'Mismatch for computed STH root.  Inclusion not guaranteed.'
    return match, None

#def base64_to_bytes(s: str) -> bytes:
#    return base64.b64decode(s)

def compute_rfc6962_parent(left: bytes, right: bytes) -> bytes:
    """Compute RFC 6962 internal node hash (SHA256(0x01 || left || right))."""
    return hashlib.sha256(b"\x01" + left + right).digest()

def compute_merkle_root(leaf_hash: bytes, leaf_index: int, audit_path: list, tree_size: int, verbose: bool = False):
    """
    Compute Merkle root from leaf hash and audit path.
    
    Algorithm based on RFC 6962 Section 2.1.1:
    - Walk up from leaf to root
    - At each level, determine if current node is left or right child
    - Combine with sibling from audit path accordingly
    """
    if verbose:
        logging.debug(f"Tree size: {tree_size}")
        logging.debug(f"Leaf index: {leaf_index}")
        logging.debug(f"Audit path length: {len(audit_path)}")
        logging.debug(f"Starting leaf_hash (b64): {base64.b64encode(leaf_hash).decode()}\n")
    
    node_hash = leaf_hash
    node_index = leaf_index
    last_node_index = tree_size - 1
    
    for level, sibling in enumerate(audit_path):
        if verbose:
            logging.debug(f"Level {level:02d}: node_index={node_index}, last_node={last_node_index}")
        
        # Determine if current node is left or right child
        # This is based on whether node_index is even or odd at this level AND whether there are nodes to the right
        
        if node_index % 2 == 0:
            # Node index is even - could be left child
            # Check if there's a right sibling by seeing if last_node > node_index at this level
            if node_index == last_node_index:
                # We're at the rightmost position, but still have audit path
                # This means we need to hash with sibling on the left
                node_hash = compute_rfc6962_parent(sibling, node_hash)
                if verbose:
                    logging.debug(f"  Rightmost node: parent = hash(sibling || node)")
            else:
                # Normal left child with right sibling
                node_hash = compute_rfc6962_parent(node_hash, sibling)
                if verbose:
                    logging.debug(f"  Left child: parent = hash(node || sibling)")
        else:
            # Node index is odd - right child
            # Sibling is on the left
            node_hash = compute_rfc6962_parent(sibling, node_hash)
            if verbose:
                logging.debug(f"  Right child: parent = hash(sibling || node)")
        
        if verbose:
            logging.debug(f"  sibling (hex): {sibling.hex()}")
            logging.debug(f"  parent  (b64): {base64.b64encode(node_hash).decode()}\n")
        
        # Move to parent level
        node_index //= 2
        last_node_index //= 2
    
    return node_hash    