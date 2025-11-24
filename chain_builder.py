import logging
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa, padding
from helper_functions import calculate_spki_hash, get_spkid, get_akid, is_self_signed
from typing import Sequence, Optional, Tuple

import helper_functions

def get_root_cert(
        server_chain: Sequence[x509.Certificate], 
        root_store: Sequence[x509.Certificate]) -> Tuple[Optional[x509.Certificate], Optional[str], Optional[str], Optional[x509.Certificate]]:
    """
    Given an x509.Certificate chain and trusted root store, attempt to resolve and verify the root CA certificate for the server's certificate chain.

    Args:
        chain (Sequence): Ordered x509 certificate chain presented by the server (leaf first, intermediates, and optionally a root cert)
        root_store (Sequence[x509.Certificate]): List of trusted root certificates to match against.
    Returns:
        Tuple[Optional[x509.Certificate], Optional[str], Optional[str], Optional[x509.Certificate]]: (root_cert, claimed_root, verification_error, self_signed)
            root_cert:          Matched root cert from root_store, or None if no match.
            claimed_root:       CN (preferred) or full RFC 4514 subject string of the matched root cert, or None if no root identified.
            verification_error: Any error encountered during certificate chain verification
            self_signed:        Self-signed x509.Certificate object
    """
    logging.warning(f"-----------------------------------Entering get_root_cert()---------------------------------------")
    logging.info(f'Number of certifi + custom trusted root CA entries: {len(root_store)}')

    for i, cert in enumerate(server_chain):
        logging.debug(f'Cert #{i}: subject = {cert.subject.rfc4514_string()}')
        logging.debug(f'Cert #{i}: issuer  = {cert.issuer.rfc4514_string()}')
        logging.debug(f'Cert #{i}: hash: {cert.fingerprint(hashes.SHA256()).hex()}')
        logging.debug('------------------')

    # If using self-signed cert...
    if len(server_chain) == 1:
        # Return self-signed certificates as pseudo-root.
        #self_signed = server_chain[0].issuer.rfc4514_string()
        cert = server_chain[0]
        # Confirm it's properly self-signed before returning...
        if helper_functions.is_self_signed(cert):
            return None, None, None, cert
        else:  # Signature verification failed
            if cert.subject == cert.issuer:
                verification_error = f"<br>&emsp;&emsp;▶ Invalid digital signature for self-signed certificate:<br>&emsp;&emsp;&emsp;<code>{cert.subject.rfc4514_string()}</code>"
                return None, None, verification_error, None
            
    logging.info(f'Length of presented chain: {len(server_chain)}')

    for i, cert in enumerate(server_chain):
        # Label selection logic
        if i == 0:
            label = "Leaf cert"
        elif cert.subject == cert.issuer:
            label = "Root cert"
        elif i == 1:
            label = "Issuing CA"
        else:
            label = f"Intermediate CA #{i-1}" if i > 2 else "Subordinate CA"
       
        aki_extension = get_akid(cert)
        if aki_extension:
            aki_extension = aki_extension.hex()

        fields = {
            "Subject": cert.subject.rfc4514_string(),
            "Issuer": cert.issuer.rfc4514_string(),
            "Serial number": cert.serial_number,
            "Serial number (hex)": hex(cert.serial_number),
            "Not valid before UTC": cert.not_valid_before_utc,
            "Not valid after UTC": cert.not_valid_after_utc,
            "Authority Key ID (AKI)": aki_extension,
            "Subject Key ID (SKI)": get_spkid(cert).hex(),
            "Subject PubKey (SHA256)": calculate_spki_hash(cert, "SHA256", hex=True),
            "Fingerprint (SHA1)": cert.fingerprint(hashes.SHA1()).hex(),
            "Fingerprint (SHA256)": cert.fingerprint(hashes.SHA256()).hex(),            
        }
        
        # Compute padding width (based on longest field name)
        max_key_len = max(len(k) for k in fields)
        pad = max_key_len + 2

        logging.warning(f"{label}:")
        for key, value in fields.items():
            prefix = f"  {key + ':':<{pad}}"
            logging.info(f"{prefix}{value}")

    # Verify each link in the chain, starting from leaf and working up to the last CA cert
    for issuer, subject in zip(server_chain[1:], server_chain[:-1]):
        try:
            verify_signature(subject, issuer)
            logging.info(f"Signature verification successful for {subject.subject.rfc4514_string()}.")
        except Exception as e:
            verification_error = f"Cert chain verification failed between '{subject.subject.rfc4514_string()}' and '{issuer.subject.rfc4514_string()}': {e}"
            logging.critical(verification_error)
            logging.critical(f"Aborting further verification attempts.")
            return None, None, verification_error, None

    # Verify last cert in chain against a trusted root anchors 
    last_cert = server_chain[-1]

    # Compensate for cases where webserver included root cert in chain
    # Note - If using DANE usage type 2, a webserver may legitimately include the root cert in the cert chain it presents
    # TODO: Add additional logic to handle DANE usage types 2 and 3 when using private CA or self-signed leaf certs.
    root_in_chain = False
    if last_cert.subject == last_cert.issuer:
        logging.debug('Note: Root cert included in cert chain from webserver.')
        if len(server_chain) > 2:
            last_cert = server_chain[-2]
        root_in_chain = True

    for root in root_store:
        if root.subject == last_cert.issuer:
            try:
                verify_signature(last_cert, root)

                if root_in_chain:
                    # In this case, the root cert information was already logged earlier and can simply return the verified root,
                    # provided that it matches the root we identified.
                    if root == server_chain[-1]:
                        return root, None, None, None
                    else:
                        logging.error("Root supplied in server's cert chain does not match enumerated root from trusted root store.")

                else:
                    logging.warning('Chain verified against Root CA:')
                    logging.info  (f'  Subject:                 {root.subject.rfc4514_string()}')
                    logging.info  (f'  Issuer:                  {root.issuer.rfc4514_string()}')
                    logging.info  (f'  Serial number:           {root.serial_number}')
                    logging.info  (f'  Serial number (hex):     {hex(root.serial_number)}')
                    logging.info  (f'  Not valid before UTC:    {root.not_valid_before_utc}')
                    logging.info  (f'  Not valid after UTC:     {root.not_valid_after_utc}')
                    logging.info  (f'  Subject Key ID (SKI):    {get_spkid(root).hex()}')
                    logging.info  (f'  Subject PubKey (SHA256): {calculate_spki_hash(root, "SHA256", hex=True)}'),
                    logging.info  (f'  Fingerprint (SHA1):      {(root.fingerprint(hashes.SHA1())).hex()}')
                    logging.info  (f'  Fingerprint (SHA256):    {(root.fingerprint(hashes.SHA256())).hex()}')
                    return root, None, None, None
            except Exception as e:
                logging.error(f"Root CA cert verification failed: {e}")
                continue

    logging.error(f"No trust anchor cert found!")
    return None, last_cert.issuer.rfc4514_string(), None, None

def verify_signature(subject: x509.Certificate, issuer: x509.Certificate) -> None:
    """
    Cryptographically verify that `issuer` signed `subject`.
    
    Handles RSA (PKCS#1 v1.5 and basic PSS), ECDSA, Ed25519/Ed448, and DSA.
    """
    #from cryptography.hazmat.primitives import serialization
    #logging.error(f'Subject PEM bytes: {(subject.public_bytes(serialization.Encoding.PEM)).decode("utf-8")}')
    #logging.info('-----------------------------------')
    #logging.error(f'Issuer PEM bytes: {(issuer.public_bytes(serialization.Encoding.PEM)).decode("utf-8")}')
        
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

def deduplicate_chain(cert_chain: Sequence[x509.Certificate]) -> Sequence[x509.Certificate]:
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

def build_cert_index(chain) -> Tuple[dict[str, x509.Certificate], dict[str, x509.Certificate]]:
    """Build lookup structures for efficient parent certificate resolution."""
    by_subject = {}
    by_skid = {}
    
    for cert in chain:
        # Index by subject DN
        by_subject[cert.subject.rfc4514_string()] = cert
        
        # Index by SKID if present
        skid = get_spkid(cert)
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
    raise ValueError("Could not determine leaf certificate in chain")

def find_parent(child: x509.Certificate, by_subject: dict, by_skid: dict) -> Optional[x509.Certificate]:
    """
    Find parent certificate using:
    1. Issuer DN → Subject DN match
    2. AKID → SKID match (fallback)
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
        findings:   
        
    Raises:
        ValueError: If leaf certificate cannot be determined
    """
    logging.warning("-----------------------------------Entering normalize_chain()-------------------------------------")
    findings = []
    logging.debug(f'Chain prior to de-duplication & reordering: {[cert.subject.rfc4514_string() for cert in chain]}')

    # Remove duplicates
    chain, dups = deduplicate_chain(chain)
    if dups:
        findings.append(dups)

    if len(chain) == 1:
        logging.error(f'Encountered Unchained certificate: {chain[0].subject.rfc4514_string()}')
        return chain, f'⚠️ Encountered Unchained certificate:<br><b>{chain[0].subject.rfc4514_string()}</b>'

    # Build lookup indexes
    by_subject, by_skid = build_cert_index(chain)
    
    # Find starting point (leaf certificate)
    leaf = find_leaf_cert(chain)
    
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