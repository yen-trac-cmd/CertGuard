# CertGuard

CertGuard is a **proof-of-concept** add-on for **mitmproxy** that extends TLS certificate and Certificate Authority (CA) validation **beyond what standard web browsers provide**.
It is designed for **security-conscious, technically-savvy users** who want deeper visibility into, and control over, certificate trust decisions made while browsing the Internet.

This project is **not intended for general-purpose end users**.  
Instead, CertGuard serves as a research tool and demonstration framework for improving certificate validation, enhancing trust analysis, and detecting unusual or suspicious certificate configuration errors in real-world HTTPS connections.

---

## 🔍 What CertGuard Does

- Adds **custom certificate and CA validation checks** on top of mitmproxy’s built-in functionality  
- Performs analysis such as:
  - Validation of certificates against TLSA DNS records (if published and signed via DNSSEC)
  - Restricting or prohibiting access to certificates issued by configured CAs (or CAs operating in specific countries)
  - Extracting Signed Certificate Timestamps (SCTs) from certificates, validating their digital signatures, and cryptographically verifying inclusion in the associated Certificate Transparency logs.
  - Validation of server certificates against CAA records (if published)
  - CRL/OCSP revocation checking against all certificates in the provided cert chain
  - Policy-driven error reporting 
- Displays findings in both the console and a browser-based error screen  
- Helps researchers understand why a certificate **should or should _not_ be trusted**

---

## ⚠️ Disclaimer
CertGuard intercepts/decrypts HTTPS traffic via mitmproxy and performs deep inspection of certificates and 
network metadata. Use it **only in environments for which you have authorization to decrypt network traffic**, 
and only if you understand the security implications for running proof-of-concept code!

---

## 📦 Installation

### 1. Install mitmproxy  
Follow the official installation instructions:  
https://docs.mitmproxy.org/stable/overview/installation/

Don't forget to install the Certificate Authority that mitmproxy generates for your installation.  This is covered at:
https://docs.mitmproxy.org/stable/overview/getting-started/

### 2. Create a virtual environment & clone CertGuard

```
python3 -m venv ~/CertGuard
source ~/CertGuard/bin/activate
cd ~/CertGuard
git clone https://github.com/yen-trac-cmd/CertGuard/
```

### 3. Install Python dependencies
Inside the activated virtual environment, execute:
`pip install cryptography dnspython lxml requests-cache`

### 4. Configure CertGuard
Adjust the self-documented `config.toml` configuration file to suit your needs.

- Enable/disable certificate validation modules
- Set error logging severity levels
- Configure CA and country validation rules
- Tune DANE options
- etc.


## 🚀 Running CertGuard
From the CertGuard project directory (where certguard.py resides), launch mitmproxy with the CertGuard script:
```
mitmproxy -s ./src/CertGuard/certguard.py
```

After starting mitmproxy, direct your browser or test device to use the proxy.
CertGuard will analyze certificates and display validation results in real-time.

## 🛠 Project Status
CertGuard is merely a proof-of-concept created as part of a research project and is **not** suitable for use in production environments and has **not** been code-reviewed for security vulnerabilities.  It's also a work-in-progress, so APIs, validation logic, and output formatting may evolve rapidly as features are refined.  **USE AT YOUR OWN RISK!**

Feedback, issue reports, and suggestions are welcome.