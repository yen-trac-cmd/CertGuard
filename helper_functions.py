from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dns.resolver import dns
from mitmproxy import certs
import logging

def supported_ciphers_list():
    # Read in https://testssl.sh/3.2/etc/cipher-mapping.txt and return list of both OpenSSL and IANA ciphersuite names.
    ciphers=[]
    with open('./resources/cipher-mapping.txt', 'r') as f:
        ciphers = [cipher_name for line in f for cipher_name in line.split()[2:4]]
    return ciphers

def cert_to_x509(cert):
    # Convert a mitmproxy Cert or OpenSSL.crypto.X509 into a cryptography.x509.Certificate.
    pem_bytes = cert.to_pem()  # returns standard PEM
    return x509.load_pem_x509_certificate(pem_bytes, default_backend())

def get_cert_domains(x509_cert: certs.Cert) -> list[str]:
    """
    Extract CN and DNS SubAltNames from a mitmproxy.certs.Cert.

    Args:
        x509_cert (mitmproxy.certs.Cert)

    Returns:
        list: A de-duplicated list of FQDN strings, in lower-case, found in the supplied certificate.
    """
    domains = set()

    # Subject CN
    for attr in x509_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
        domains.add(attr.value.lower())

    # SANs
    try:
        san_ext = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value.get_values_for_type(x509.DNSName):
            domains.add(name.lower())
    except x509.ExtensionNotFound:
        pass

    return list(domains)

def is_zone_signed(domain):
    logging.warning(f"===================================Entering is_zone_signed()========================================")
    ######## will DNS *always* return SOA with any query for non-existent record?  If so, chase that.  ...If not, do devolution thing to get SOA.  ...THEN query for NS.
    try:
        ns_query = dns.resolver.query(domain, dns.rdatatype.NS)
        logging.error(f'ns_query response when checking against "{domain}": {str(ns_query[0])}')

        nameserver = str(ns_query[0])
        logging.info(f"Authoritative nameserver '{nameserver}'' found for domain '{domain}'.")

        # Query the authoritative nameserver for DNSKEY records to determine if zone is signed
        nameserver_ip = dns.resolver.query(nameserver, dns.rdatatype.A)[0].to_text()
        query_message = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.udp(query_message, nameserver_ip)
            
        if response.answer and any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer):
            logging.info(f"The {domain} zone appears to be DNSSEC-signed (found RRSIG records).")
            return True
        else:
            logging.info(f"The zone {domain} zone does NOT appear to be DNSSEC-signed (no RRSIG records found).")
            return False
                
    except dns.resolver.NXDOMAIN:
        logging.error(f"Error: The {domain} domain does not exist.")
        return False
    except dns.resolver.NoAnswer:
        logging.error(f"Warning: No NS records found for '{domain}', or no DNSKEY records returned.")
        return False
    except dns.exception.Timeout:
        logging.error(f"Error: DNS query for {domain} timed out.")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False
