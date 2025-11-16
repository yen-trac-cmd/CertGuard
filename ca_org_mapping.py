'''
Authoritative CA references for acceptable CA domain identifiers: 
Amazon:         https://www.amazontrust.com/repository/
                https://www.amazontrust.com/repository/cp-cps__2-0.pdf
certSIGN:       https://www.certsign.ro/ro/depozitar/
                https://www.certsign.ro/en/document/certsign-ssl-dv-ca-class-3-g2-certification-practice-statement/
D-Trust:        https://www.d-trust.net/en/support/repository
                https://www1.d-trust.net/internet/files/D-TRUST_TSPS.pdf
DigiCert:       https://docs.digicert.com/en/certcentral/manage-certificates/dns-caa-resource-record-check.html
                https://www.digicert.com/content/dam/digicert/pdfs/legal/digicert-public-trust-cpcps-7.06.pdf
Entrust:        https://www.entrust.com/legal-compliance/entrust-certificate-services-repository
Fastly:         https://www.certainly.com/repository/index.html
Gehirn MCA:     https://www.gehirn.jp/mca/repository/
GlobalSign:     https://www.globalsign.com/en/repository
Google:         https://pki.goog/repository/
GRCA:           https://grca.nat.gov.tw/GRCAeng/3-1.html
Let's Encrypt:  https://letsencrypt.org/documents/isrg-cp-cps-v5.9/#4.2.1-performing-identification-and-authentication-functions 
Microsoft:      https://www.microsoft.com/pkiops/docs/repository.htm
                https://www.microsoft.com/pkiops/Docs/Content/policy/Microsoft_PKI_Services_public_tls_CPS_v3.3.2.pdf
Sectigo/Comodo: https://www.sectigo.com/legal 
                https://www.sectigo.com/uploads/files/Sectigo_TLS_CPS_v6_1_1.pdf
SHECA:          https://assets-cdn.sheca.com/documents/UniTrust%20Certification%20Practice%20Statement%20v3.8.1.pdf 
SSL.com:        https://www.ssl.com/repository/
WoTrus:         https://www.wosign.com/CA/policy.htm


Useful cross-references: 
  - https://www.entrust.com/knowledgebase/ssl/certification-authority-authorization-caa-record-ca-values
  - https://web.archive.org/web/20250627075316/https://ccadb.my.salesforce-sites.com/ccadb/AllCAAIdentifiersReport
  - https://web.archive.org/web/20250723091652/https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCerts
  - 
'''

# Map common Issuing CA Organization ("O=" field from x.509 Subject) to CAA identifier(s)
# Initially limited to Intermediate CAs appearing 10 or more times on Mozilla's list at https://wiki.mozilla.org/CA/Intermediate_Certificates.
# Leaving out entry for "泰尔认证中心有限公司", which corresponds to "TL Certification Center Co., Ltd." based out of China.  
#    It chains to Sectigo and Asseco root CAs, but I cannot locate a CPS statement for them and do not trust them to issue certs for domains
#    that have only/explicitly authorized Sectigo or Asseco to issue certs.
ca_org_to_caa  = {
  "行政院": ["gca.nat.gov.tw"],
  "AC CAMERFIRMA S.A.": ["camerfirma.com"],
  "ACCV": ["accv.es"],
  "Actalis S.p.A.": ["actalis.it"],
  "AffirmTrust": ["affirmtrust.com"],
  "Amazon Trust Services": ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com", "aws.amazon.com"],
  "Amazon": ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com", "aws.amazon.com"],
  "Apple Inc.": ["pki.apple.com"],
  "Asseco Data Systems S.A.": ["certum.pl", "certum.eu"],
  "BEIJING CERTIFICATE AUTHORITY": ["bjca.cn"],
  "Buypass AS-983163327": ["buypass.com"],
  "COMODO CA Limited": ["comodoca.com", "sectigo.com"],
  "Certainly": ["certainly.com"],
  "Certigna": ["certigna.fr", "certigna.com"],
  "CERTSIGN SA": ["certsign.ro"],  
  "certSIGN": ["certsign.ro"],
  "Certum": ["certum.pl"],
  "China Financial Certification Authority": ["cfca.com.cn"],
  "Cybertrust Japan Co., Ltd.": ["cybertrust.co.jp", "cybertrust.ne.jp"],
  "D-Trust GmbH": ["d-trust.net", "dtrust.de", "d-trust.de"],
  "Deutsche Telekom Security GmbH": ["telesec.de" , "pki.dfn.de" , "dfn.de"],
  "DigiCert, Inc.": [
      "www.digicert.com",
      "digicert.com",
      "digicert.ne.jp",
      "cybertrust.ne.jp",
      "thawte.com",
      "geotrust.com",
      "rapidssl.com",
      "symantec.com",
      "volusion.digitalcertvalidation.com",
      "stratossl.digitalcertvalidation.com",
      "intermediatecertificate.digitalcertvalidation.com",
      "1and1.digitalcertvalidation.com",
      "amazon.com",
      "amazontrust.com",
      "awstrust.com",
      "amazonaws.com",
      "digitalcertvalidation.com",
      "quovadisglobal.com",
      "pkioverheid.nl"
    ],
  "DigiCert Inc": [
      "www.digicert.com",
      "digicert.com",
      "digicert.ne.jp",
      "cybertrust.ne.jp",
      "thawte.com",
      "geotrust.com",
      "rapidssl.com",
      "symantec.com",
      "volusion.digitalcertvalidation.com",
      "stratossl.digitalcertvalidation.com",
      "intermediatecertificate.digitalcertvalidation.com",
      "1and1.digitalcertvalidation.com",
      "amazon.com",
      "amazontrust.com",
      "awstrust.com",
      "amazonaws.com",
      "digitalcertvalidation.com",
      "quovadisglobal.com",
      "pkioverheid.nl"
    ],
  "Digidentity B.V.": ["www.pkioverheid.nl"],
  "EDICOM": ["edicomgroup.com"],
  "EDICOM CAPITAL SL": ["edicomgroup.com"],
  "eMudhra Inc": ["emsign.com"],
  "eMudhra Technologies Limited": ["emsign.com"],
  "Encryption Everywhere CA": ["digicert.com"],
  "Entrust": ["entrust.net"],
  "Entrust, Inc.": ["entrust.net"],
  "Entrust Limited": ["entrust.net"],
  "Entrust Corporation": ["entrust.net"],
  "Gehirn Inc.": ["sectigo.com", "usertrust.com", "trust-provider.com"],
  "Genious Communications": ["sectigo.com", "usertrust.com", "trust-provider.com"],
  "GeoTrust": ["geotrust.com"],
  "GlobalSign nv-sa": ["globalsign.com"],
  "GlobalSign": ["globalsign.com"],
  "GoDaddy.com, Inc.": ["godaddy.com", "starfieldtech.com"],
  "Google Trust Services LLC": ["pki.goog"],
  "Google Trust Services": ["pki.goog"],
  "Hellenic Academic and Research Institutions CA": ["harica.gr"],
  "IdenTrust": ["identrust.com"],
  "IdenTrust, Inc.": ["identrust.com"],
  "Internet Security Research Group": ["letsencrypt.org"],
  "Let's Encrypt": ["letsencrypt.org"],
  "Microsec Ltd.": ["e-szigno.hu"],
  "Microsoft Corporation": ["microsoft.com", "digicert.com"],
  "NETLOCK Kft.": ["netlock.hu", "netlock.net", "netlock.eu", "netlock.com"],
  "QuoVadis Limited": ["quovadisglobal.com"],
  "QuoVadis Trustlink B.V.": ["quovadisglobal.com", "www.pkioverheid.nl"],
  "QuoVadis Trustlink Deutschland GmbH": ["quovadisglobal.com"],
  "QuoVadis Trustlink Schweiz AG": ["quovadisglobal.com"],
  "RapidSSL": ["rapidssl.com"],
  "SECOM Trust Systems CO.,LTD.": ["secomtrust.net"],
  "Sectigo Limited": ["sectigo.com", "usertrust.com", "trust-provider.com", "comodo.com", "comodoca.com", "entrust.net", "affirmtrust.com"],
  "SSL Corp": ["ssl.com", "entrust.net", "affirmtrust.com"],
  "SSL Corporation": ["ssl.com", "entrust.net", "affirmtrust.com"],
  "Starfield Technologies": ["starfieldtech.com"],
  "Starfield Technologies, Inc.": ["starfieldtech.com", "amazon.com"],
  "SwissSign AG": ["swisssign.com"],
  "TAIWAN-CA": ["twca.com.tw"],
  "TAIWAN-CA Inc.": ["twca.com.tw"],
  "Telia Company AB": ["telia.com"],
  "Telia Finland Oyj": ["telia.com"],
  "TeliaSonera": ["telia.com"],
  "TrustAsia Technologies, Inc.": ["trustasia.com"],
  "TWCA": ["twca.com.tw"],
  "The USERTRUST Network": ["sectigo.com", "usertrust.com", "trust-provider.com", "comodo.com", "comodoca.com", "entrust.net", "affirmtrust.com"],
  "Trustwave Holdings, Inc.": ["trustwave.com", "securetrust.com", "vikingcloud.com"],
  "UniTrust": ["sheca.com", "imtrust.cn", "wwwtrust.cn"],
  "Viking Cloud, Inc.": ["trustwave.com", "securetrust.com", "vikingcloud.com"],
  "Verokey": ["digicert.com"],
  "WoSign CA Limited": ["wosign.com"],
  "WoTrus CA Limited": ["wotrust.com"],
  "ZeroSSL": ["zerossl.com"],
}
