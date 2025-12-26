import logging

from cryptography.exceptions import InvalidSignature
from checks.helper_functions import is_self_signed
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa, padding
from typing import Sequence, Optional, Tuple
from utils.x509 import calculate_spki_hash, get_akid, get_pubkey_info, get_skid

def get_root_cert(
        server_chain: Sequence[x509.Certificate], 
        root_cert: Optional[x509.Certificate], 
        trusted_roots_by_ski: dict,
        deprecated_roots: list
    ) -> Tuple[Optional[x509.Certificate], Optional[str], Optional[str], Optional[x509.Certificate], Optional[str]]:
    """
    Given an x509.Certificate chain and trusted root store, attempt to resolve and verify the root CA certificate for the server's certificate chain.

    Args:
        server_chain:            Ordered x509 certificate chain presented by the server (leaf first, intermediates, and optionally a root cert)
        root_cert:               Root cert if included in original cert chain from server, or already enumerated from AIA chasing.
        trusted_roots_by_ski:    List of trusted root certificates to match against.
    Returns:
        Tuple[Optional[x509.Certificate], Optional[str], Optional[str], Optional[x509.Certificate], Optional[str]]: (root_cert, claimed_root, verification_error, self_signed, tag)
          1. root_cert:          Matched root cert from root_store, or None if no match.
          2. claimed_root:       CN (preferred) or full RFC 4514 subject string of the matched root cert, or None if no root identified.
          3. verification_error: Any error encountered during certificate chain verification
          4. self_signed:        Self-signed x509.Certificate object
          5. tag:                "Trusted", "DEPRECATED", "UNTRUSTED", "UNKNOWN", "ERROR", or "INVALID".
              - Trusted roots are those found in local root trust store.
              - Deprecated roots are those that, while still technically valid, are considered deprecated by common root programs.
              - Untrusted roots are those enumerated through AIA fetching and and not present in local trust store.
              - Unknown roots are not present in the local store and cannot be fetched via AIA.
              - An "invalid" tag indicates that the provided cert chain does not cryptographically verify against the supplied (or fetched) root.
              - The "error" tag indicates some other type of exception occurred while attempting to verify a digital signature.

    """
    logging.warning(f"-----------------------------------Entering get_root_cert()---------------------------------------")

    for i, cert in enumerate(server_chain):
        logging.debug(f'Cert #{i}: subject = {cert.subject.rfc4514_string()}')
        logging.debug(f'Cert #{i}: issuer  = {cert.issuer.rfc4514_string()}')
        #logging.debug(f'Cert #{i}: hash: {cert.fingerprint(hashes.SHA256()).hex()}')
        logging.debug('------------------')

    logging.info(f'Length of presented chain: {len(server_chain)}')

    for i, cert in enumerate(server_chain):
        # Label selection logic
        if cert.subject == cert.issuer and len(server_chain) == 1:
            label = "Unchained cert"
        elif cert.subject == cert.issuer:
            label = "Root cert"
        elif i == 0:
            label = "Leaf cert"
        elif i == 1:
            label = "Issuing CA"
        else:
            label = f"Intermediate CA #{i-1}" if i > 2 else "Subordinate CA"
       
        aki_extension = get_akid(cert)
        if aki_extension:
            aki_extension = aki_extension.hex()
        algo, bitlength = get_pubkey_info(cert)

        fields = {
            "Subject": cert.subject.rfc4514_string(),
            "Issuer": cert.issuer.rfc4514_string(),
            "Serial number": cert.serial_number,
            "Serial number (hex)": hex(cert.serial_number),
            "Not valid before UTC": cert.not_valid_before_utc,
            "Not valid after UTC": cert.not_valid_after_utc,
            "Public Key Algorithm": f'{algo}-{bitlength}',
            "Signature Algorithm": cert.signature_algorithm_oid._name,
            "Authority Key ID (AKI)": aki_extension,
            "Subject Key ID (SKI)": get_skid(cert).hex(),
            "Subject PubKey (SHA256)": calculate_spki_hash(cert, "SHA256", hex=True),
            "Fingerprint (SHA1)": cert.fingerprint(hashes.SHA1()).hex(),
            "Fingerprint (SHA256)": cert.fingerprint(hashes.SHA256()).hex(),            
        }
        
        # Compute padding width (based on longest field name)
        max_key_len = max(len(k) for k in fields)
        pad = max_key_len + 2

        if label == "Root cert":
            pass
        else:
            logging.warning(f"{label}:")
            for key, value in fields.items():
                prefix = f"  {key + ':':<{pad}}"
                logging.info(f"{prefix}{value}")

    # Check for unchained or self-signed cert...
    if len(server_chain) == 1:
        # Check to see if unchained cert is self-signed.  If so, return as pseudo-root.
        cert = server_chain[0]
        if is_self_signed(cert):
            return None, None, None, cert, 'Self-signed'
        elif cert.subject == cert.issuer:   
            # This indicates a bad signature on a supposedly self-signed cert
            verification_error = f"<br>&emsp;&emsp;▶ Invalid digital signature for self-signed certificate:<br>&emsp;&emsp;&emsp;<code>{cert.subject.rfc4514_string()}</code>"
            return None, None, verification_error, None, 'INVALID'
        else:  
            # If arrived here, cert is fully unchained, not self-signed, and does not contain AIA information to fetch issuer CA cert.
            return None, cert.issuer.rfc4514_string(), None, None, 'UNKNOWN'

    # Verify each link in the chain, starting from leaf and working up to the last CA cert
    for issuer, subject in zip(server_chain[1:], server_chain[:-1]):
        try:
            verify_signature(subject, issuer)
            logging.info(f"Signature verification successful for {subject.subject.rfc4514_string()}.")
        except Exception as e:
            verification_error = f"Cert chain verification failed between '{subject.subject.rfc4514_string()}' and '{issuer.subject.rfc4514_string()}': {e}"
            logging.critical(verification_error)
            logging.critical(f"Aborting further verification attempts.")
            return None, None, verification_error, None, 'ERROR'

    # Verify last cert in chain against a trusted root anchors 
    last_cert = server_chain[-1]
    verification_error = None

    # Compensate for cases where webserver included root cert in chain
    # TODO: Add additional logic to handle DANE usage types 2 and 3 when using private CA or self-signed leaf certs.
    root_in_chain = False
    if last_cert.subject == last_cert.issuer:
        if len(server_chain) > 2:
            last_cert = server_chain[-2]
        root_in_chain = True

    if root_cert is None:
        error = f'Unable to fetch missing certs from certificate chain to identify root cert.'
        logging.error(error)
        return None, last_cert.issuer.rfc4514_string(), f'<br>&emsp;&emsp;▶ {error}', None, 'UNKNOWN'
    
    try:
        verify_signature(last_cert, root_cert)
    except InvalidSignature:
        verification_error = (f'Certificate chain failed to verify against Root CA cert.')
        logging.error(verification_error)
        return None, last_cert.issuer.rfc4514_string(), f'<br>&emsp;&emsp;▶ {verification_error}', None, 'INVALID'
    except Exception as e:
        verification_error = f'Encountered exception while attempting digital signature verification: {e}'
        logging.error(verification_error)
        return None, last_cert.issuer.rfc4514_string(), f'<br>&emsp;&emsp;▶ {verification_error}', None, 'ERROR'

    # Despite successful signature verification, the passed-in root_cert could be an enumerated root fetched from AIA and not
    # actually present in the local roots trust store.  Determine if it's trusted or not for later logic.
    root_skid = get_skid(root_cert)
    root_is_trusted = root_skid in trusted_roots_by_ski
    root_is_deprecated = root_cert.fingerprint(hashes.SHA256()) in deprecated_roots

    if root_is_deprecated:
        tag = 'DEPRECATED'
    elif root_is_trusted:
        tag = 'Trusted'
    else:
        tag = 'UNTRUSTED'

    algo, bitlength = get_pubkey_info(root_cert)
    logging.warning(f'{tag} Root CA:')
    logging.info  (f'  Subject:                 {root_cert.subject.rfc4514_string()}')
    logging.info  (f'  Issuer:                  {root_cert.issuer.rfc4514_string()}')
    logging.info  (f'  Serial number:           {root_cert.serial_number}')
    logging.info  (f'  Serial number (hex):     {hex(root_cert.serial_number)}')
    logging.info  (f'  Not valid before UTC:    {root_cert.not_valid_before_utc}')
    logging.info  (f'  Not valid after UTC:     {root_cert.not_valid_after_utc}')
    logging.info  (f'  Public Key Algorithm:    {algo}-{bitlength}')
    logging.info  (f'  Signature Algorithm:     {root_cert.signature_algorithm_oid._name}')
    logging.info  (f'  Subject Key ID (SKI):    {get_skid(root_cert).hex()}')
    logging.info  (f'  Subject PubKey (SHA256): {calculate_spki_hash(root_cert, "SHA256", hex=True)}'),
    logging.info  (f'  Fingerprint (SHA1):      {(root_cert.fingerprint(hashes.SHA1())).hex()}')
    logging.info  (f'  Fingerprint (SHA256):    {(root_cert.fingerprint(hashes.SHA256())).hex()}')
    logging.info(f"Signature verification successful for {last_cert.subject.rfc4514_string()}.")
    
    if root_is_deprecated:
        logging.warning('Cert chain anchors to deprecated Root CA cert.')
        return root_cert, None, verification_error, None, tag
    elif root_is_trusted:
        logging.info('Cert chain anchors to Trusted Root CA cert')
        return root_cert, None, verification_error, None, tag
    else:
        logging.error(f"Cert chain anchored to UNTRUSTED root CA!")
        return root_cert, last_cert.issuer.rfc4514_string(), verification_error, None, tag

def verify_signature(subject: x509.Certificate, issuer: x509.Certificate) -> None:
    """
    Cryptographically verify that `issuer` signed `subject`.
    
    Supports RSA (PKCS#1 v1.5 and basic PSS), ECDSA, Ed25519/Ed448, and DSA.

    Raises TypeError if cannot determine digital signature type.
    """
        
    pubkey = issuer.public_key()
    oid = subject.signature_algorithm_oid
    h = subject.signature_hash_algorithm  # a HashAlgorithm instance, or None for EdDSA

    if isinstance(pubkey, rsa.RSAPublicKey):
        # Handle RSA-PSS vs RSA-PKCS1v1.5
        if oid == x509.SignatureAlgorithmOID.RSASSA_PSS:
            # Best-effort PSS parameters: MGF1 with same hash; salt len = hash length.
            # (Parsing explicit PSS params is possible but longer; this covers common cases.)
            pubkey.verify(
                signature=subject.signature,
                data=subject.tbs_certificate_bytes,
                padding=padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size),
                algorithm=h,
            )
        else:
            pubkey.verify(signature=subject.signature, data=subject.tbs_certificate_bytes, padding=padding.PKCS1v15(), algorithm=h)

    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        # ECDSA takes a signature algorithm wrapper with the hash
        pubkey.verify(signature=subject.signature, data=subject.tbs_certificate_bytes, signature_algorithm=ec.ECDSA(h))

    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        pubkey.verify(subject.signature, subject.tbs_certificate_bytes)

    elif isinstance(pubkey, ed448.Ed448PublicKey):
        pubkey.verify(subject.signature, subject.tbs_certificate_bytes)

    elif isinstance(pubkey, dsa.DSAPublicKey):
        pubkey.verify(signature=subject.signature, data=subject.tbs_certificate_bytes, algorithm=h,)

    else:
        raise TypeError(f"Unsupported public key type: {type(pubkey)}")

def deduplicate_chain(cert_chain: Sequence[x509.Certificate]) -> Tuple[Sequence[x509.Certificate], Optional[str]]:
    """ Removes duplicate certs from provided certificate chain """
    seen = set()
    unique_chain = []
    findings = []
    for cert in cert_chain:
        fp = cert.fingerprint(hashes.SHA256())
        if fp not in seen:
            seen.add(fp)
            unique_chain.append(cert)
        else:
            finding = f"⚠️ Duplicate certificate detected: {cert.subject.rfc4514_string()}"
            logging.warning(finding)
            findings.append(finding)
    return unique_chain, "<br>".join(findings)

def build_cert_index(store) -> Tuple[dict[str, x509.Certificate], dict[str, x509.Certificate]]:
    """Build lookup structures for efficient parent certificate resolution."""
    by_subject = {}
    by_skid = {}
    
    for cert in store:
        # Index by subject DN
        by_subject[cert.subject.rfc4514_string()] = cert
        
        # Index by SKID if present
        skid = get_skid(cert)
        if skid:
            by_skid[skid] = cert
    
    return by_subject, by_skid

def find_leaf_cert(chain: list[x509.Certificate]) -> x509.Certificate:
    """
    Identify the leaf certificate as the one whose subject does NOT appear as any other certificate's issuer.
    """
    all_issuers = {cert.issuer.rfc4514_string() for cert in chain}
    for cert in chain:
        if cert.subject.rfc4514_string() not in all_issuers:
            return cert
    
    # If reach here, was not able to identify leaf cert
    return None

def find_parent(child: x509.Certificate, by_subject: dict, by_skid: dict) -> Optional[x509.Certificate]:
    """
    Find parent certificate using:
    1. Issuer DN -> Subject DN match
    2. AKID -> SKID match (fallback)
    """
    # Primary: Match by DN
    parent = by_subject.get(child.issuer.rfc4514_string())
    if parent:
        return parent
    
    # Fallback: Match by key identifiers
    akid = get_akid(child)
    if akid:
        return by_skid.get(akid)
    
    return None

def normalize_chain(chain: list[x509.Certificate]) -> Tuple[Sequence[x509.Certificate], Optional[str]]:
    """
    Return a deduplicated, properly ordered certificate chain.
    
    Args:
        chain:      List of x509.Certificate objects in any order
        
    Returns:
        ordered:    List of certificates ordered from leaf to root
        findings:   Warnings encountered during normalization routines

    """
    logging.warning("-----------------------------------Entering normalize_chain()-------------------------------------")
    findings = []
    logging.debug(f'Found {len(chain)} certs in server-supplied chain prior to de-duplication & reordering:')
    for i, cert in enumerate(chain):
        logging.debug(f' - Cert {i}: {cert.subject.rfc4514_string()}')
        #from cryptography.hazmat.primitives import serialization
        #pem_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
        #logging.debug(pem_bytes.decode('utf-8'))

    # Remove duplicates
    chain, dups = deduplicate_chain(chain)
    if dups:
        findings.append(dups)

    if len(chain) == 1:
        logging.error(f'Encountered Unchained certificate: {chain[0].subject.rfc4514_string()}')
        return chain, f'⚠️ Encountered Unchained certificate:<br>&emsp;&emsp;<b>{chain[0].subject.rfc4514_string()}</b>'

    # Build lookup indexes
    by_subject, by_skid = build_cert_index(chain)
    
    # Find starting point (leaf certificate)
    leaf = find_leaf_cert(chain)
    
    if not leaf:
        leaf = chain[0]
        findings.append("⚠️ Could not programmatically verify leaf certificate in chain.")
    
    # Walk the chain from leaf to root
    ordered = []
    seen = set()
    current = leaf
    
    while current and current not in seen:
        ordered.append(current)
        seen.add(current)
        current = find_parent(current, by_subject, by_skid)
    
    if chain != ordered:
        findings.append(f"⚠️ Certificate chain out-of-order.")
    
    return ordered, "<br>".join(findings)