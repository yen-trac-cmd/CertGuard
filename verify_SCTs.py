import base64
import datetime
import hashlib
import json
import json
import logging  
import os
import requests
import time
from helper_functions import get_cert_domains
from cryptography import x509, exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import  Encoding, PublicFormat, load_der_public_key
from cryptography.x509.oid import ExtensionOID
from enum import IntEnum
from mitmproxy import http
#from pyasn1.codec.der import decoder as asn1_decoder, encoder as asn1_encoder
#from pyasn1_modules import rfc5280
#from pyasn1.type import univ
#from urllib.request import Request, urlopen 

# Fetch SSLMate API key from environment variable.  TODO: Migrate to proper key vault.
try:
    SSLMATE_KEY = os.environ["SSLMATE_KEY"]
except:
    logging.fatal("Please define the 'SSLMATE_KEY' environment variable with your API key from SSLMate.com.")

SSLMATE_QUERY_URL = "https://api.certspotter.com/v1/issuances"
CT_LOG_LIST_URL   = "https://www.gstatic.com/ct/log_list/v3/log_list.json"     # Google's CT Log list
LOG_LIST          = "./log_list.json"                                          # Locally cached copy of Google CT Log list
LEAF_TYPE_CERT    = b'\x00'                                                    # RFC 6962 constant
LEAF_TYPE_PRECERT = b'\x01'                                                    # RFC 6962 constant

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


def load_ct_log_list():
    # Load Chrome's CT log list, refreshing if needed, and map raw log_id bytes to metadata mapping.

    def fetch_and_cache():
        resp = requests.get(CT_LOG_LIST_URL, timeout=10)
        resp.raise_for_status()
        with open(LOG_LIST, 'wb') as f:
            f.write(resp.content)
        logging.info(f"Fetched & loaded CT log list from {CT_LOG_LIST_URL}; cached under {LOG_LIST}.")
        return resp.json()

    try:
        if not os.path.exists(LOG_LIST):
            logging.info(f"{LOG_LIST} missing; fetching current copy from {CT_LOG_LIST_URL}.")
            log_list = fetch_and_cache()
        else:
            last_modified = datetime.datetime.fromtimestamp(os.path.getmtime(LOG_LIST))
            age_days = (datetime.datetime.now() - last_modified).days
            size = os.path.getsize(LOG_LIST)

            if age_days > 0 or size == 0:
                logging.info(f"{LOG_LIST} is stale (age={age_days}d, size={size} bytes); refreshing with latest authoritative copy from {CT_LOG_LIST_URL}.")
                try:
                    log_list = fetch_and_cache()
                except Exception as e:
                    logging.error(f"Failed to refresh Certificate Transparency log list from {CT_LOG_LIST_URL}: {e}; using cached copy.")
                    with open(LOG_LIST, 'rb') as f:
                        log_list = json.load(f)
            else:
                with open(LOG_LIST, 'rb') as f:
                    log_list = json.load(f)
                logging.info(f"Successfully loaded cached Google Certificate Transparency log list from {LOG_LIST}.")

        # Transform log_list mapping
        mapping = {}
        for operator in log_list.get("operators", []):
            for entry in operator.get("logs", []):
                key_b64 = entry.get("key")
                log_id_b64 = entry.get("log_id")
                if not key_b64 or not log_id_b64:
                    continue

                try:
                    # Remove whitespace/newlines
                    key_b64 = "".join(key_b64.split())
                    log_id_b64 = "".join(log_id_b64.split())

                    pubkey_der = base64.b64decode(key_b64)
                    log_id_bytes = base64.b64decode(log_id_b64)

                    pubkey = serialization.load_der_public_key(pubkey_der, backend=default_backend())
                    entry["pubkey"] = pubkey
                    entry["operator_name"] = operator.get("name")

                    mapping[log_id_bytes] = entry

                except Exception as e:
                    logging.error(f"Failed to load log public key; exception: {e}")
                    continue

        return mapping

    except Exception as e:
        logging.fatal(f"Error encountered loading CT log list: {e}")
        return None

def extract_scts(flow, cert: str, ct_log_map):
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

def validate_signature(cert, issuer_cert, sct, i):
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
    pubkey = load_der_public_key(base64.b64decode(sct["ct_log_key"]))               # Loads public key of CT log server
        
    try:
        pubkey.verify(bytes.fromhex(sct["signature"]), sct_data, ec.ECDSA(hashes.SHA256()))           # Validates SCT signature against sct_data structure defined above
        logging.info(f"   SCT #{i} digital signature verified")
        return True
    except exceptions.InvalidSignature:
        logging.error("  SCT signature FAILED to validate!!")
        return False
        
def check_ctlog_inclusion(flow, leaf_cert):
    logging.warning(f"-----------------------------------Entering check_ctlog_inclusion()--------------------------------------------------")
    leaf_cert_sha256 = leaf_cert.fingerprint(hashes.SHA256()).hex()
    leaf_precert_tbs_sha256 = hashlib.sha256(leaf_cert.tbs_precertificate_bytes).hexdigest()
    
    logging.info(f'Leaf cert SHA256 fingerprint:   {leaf_cert_sha256}')
    logging.debug(  f'  - tbs_precertificate_bytes:   {base64.b64encode(leaf_cert.tbs_precertificate_bytes).decode()}')
    logging.info(f'  - Leaf precert TBS SHA256:    {leaf_precert_tbs_sha256} ')

    # TODO - Insert code here to perform local SCT signature verification + inclusion proofing depending on CT validation level configured in config.toml.

    # Gets all SANs in cert.  We won't check against all, but this lets us check for wildcard entries.
    cert_domains = get_cert_domains(leaf_cert)    
    fqdn = (flow.request.pretty_host).lower()
    lower_case_cert_domains = [fqdn.lower() for fqdn in cert_domains]
    if fqdn in lower_case_cert_domains:
        target_fqdn = fqdn
    else:
        # Check to see if FQDN in URL is handled via wildcard entry in cert
        fqdn_parts=fqdn.split(".")
        if len(fqdn_parts) > 2:
            base_domain = ".".join(fqdn_parts[1:])
            if f'*.{base_domain}' in cert_domains:
                target_fqdn = f'*.{base_domain}'
            else:
                logging.error(f'Cannot identify FQDN for which to query SSLMate!')
    
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
            # TODO - This failure mode results in a (potentially) false verdict that the leaf cert has not been included in CT logs.
            #        Extend the return value to include more verbose description.
            return found, revoked  # False, False

        if len(records) < 100:
            break
        after = records[-1]["id"]

    #if records == False:
    #    logging.error(f'Unable to query SSLMate for {flow.request.pretty_host}; FAILING CLOSED!')
    #    return found, revoked  # False, False
    
    if all_records == []:
        logging.error(f'Empty response from SSLMate for {flow.request.pretty_host}')
        return found, revoked  # False, False

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

    return found, revoked  
    