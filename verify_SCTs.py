import base64
import datetime
import hashlib
import logging  
import os
import requests
import sys
import time
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
    Loads the CT log list and transforms it into a dictionary of CT log entry metadata, keyed by log_id_bytes.
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
        entry = ct_log_map.get(sct.log_id)

        sct_data.append({
            "version": sct.version.name,
            "log_id_hex": sct.log_id.hex(),
            "log_id_b64": base64.b64encode(sct.log_id).decode(),
            "timestamp": sct.timestamp,
            "timestamp (unix ms)": int(sct.timestamp.timestamp()*1000),
            "extension_bytes": sct.extension_bytes.hex(),
            "entry_type": sct.entry_type.name,
            "hash_algorithm": sct.signature_hash_algorithm.name,
            "signature_algorithm": sct.signature_algorithm.name,
            "signature": sct.signature.hex(),
            "ct_log_description": entry.get("description") if entry else None,
            "ct_log_operator": entry.get("operator_name") if entry else None,
            "ct_log_key": entry.get("key") if entry else None,
            "ct_log_url": entry.get("url") if entry else None,
            "ct_log_mmd": entry.get("mmd") if entry else None,
            "ct_log_state": entry.get("state") if entry else None,
            "ct_log_temporal_interval": entry.get("temporal_interval") if entry else None,
        })
    return sct_data

def validate_signature(cert: x509.Certificate, issuer_cert: x509.Certificate, sct: dict, i: int) -> bool:
    timestamp = bytes.fromhex(hex(round(sct["timestamp"].replace(tzinfo=datetime.timezone.utc).timestamp() * 1000))[2:].zfill(16))
    issuer_public_key_hash = hashlib.sha256(issuer_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).digest()

    sct_data: bytes = bytes()
    sct_data += b"\0"                                                               # Version: 0=v1
    sct_data += b"\0"                                                               # SignatureType: 0=certificate_timestamp
    sct_data += timestamp                                                           # uint64 timestamp
    sct_data += b"\x00\x01"                                                         # LogEntryType: 0x0001=precert_entry, 0x0000=cert_entry
    sct_data += issuer_public_key_hash                                              # PreCert.opaque: issuer_key_hash[32]
    sct_data += bytes.fromhex(hex(len(cert.tbs_precertificate_bytes))[2:].zfill(6)) # PreCert.TBSCertificate.opaque: 3-byte-length 
    sct_data += cert.tbs_precertificate_bytes                                       # PreCert.TBSCertificate (actual bytes)
    sct_data += b"\x00\x00"                                                         # CtExtensions.opaque: 2-byte-length(extensions)
    sct_data += b""                                                                 # CtExtensions -- no extension types are defined at this time.
    
    # Check to ensure CT Log server public key was mapped into CT Log Map
    if sct["ct_log_key"] == None:
        logging.error(f'Could not identify Certificate Transparency log server public key.')
        return False
    
    pubkey = load_der_public_key(base64.b64decode(sct["ct_log_key"]))               # Loads public key of CT log server
        
    try:
        pubkey.verify(bytes.fromhex(sct["signature"]), sct_data, ec.ECDSA(hashes.SHA256()))           # Validates SCT signature against sct_data structure defined above
        logging.info(f"   SCT #{i} digital signature verified")
        return True
    except exceptions.InvalidSignature:
        logging.error("  SCT signature FAILED to validate!!")
        return False
        
def check_ctlog_inclusion(flow: http.HTTPFlow, leaf_cert: x509.Certificate) -> Tuple[bool, bool, Optional[str]]:
    logging.warning(f"-----------------------------------Entering check_ctlog_inclusion()--------------------------------------------------")
    leaf_cert_sha256 = leaf_cert.fingerprint(hashes.SHA256()).hex()
    leaf_precert_tbs_sha256 = hashlib.sha256(leaf_cert.tbs_precertificate_bytes).hexdigest()
    
    logging.info(f'Leaf cert SHA256 fingerprint:   {leaf_cert_sha256}')
    logging.debug(f'  - tbs_precertificate_bytes:   {base64.b64encode(leaf_cert.tbs_precertificate_bytes).decode()}')
    logging.info(f'  - Leaf precert TBS SHA256:    {leaf_precert_tbs_sha256} ')

    # TODO - Insert code here to perform inclusion proofing depending on CT validation level configured in config.toml.

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
    