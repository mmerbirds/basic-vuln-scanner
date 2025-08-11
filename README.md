# Basic Vulnerability Scanner

A portable and easy-to-use vulnerability scanner that checks network services, CVEs, SSL/TLS security, directory brute force, SQL Injection, and XSS vulnerabilities.

1. Create virtualenv and install deps:
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt

2. Ensure nmap is installed (optional but recommended):
   sudo apt install nmap

3. Run scanner:
   python3 scanner.py example.com

4. GUI Version:
   python3 gui_scanner.py

Options:
  --timeout    : set HTTP request timeout (default 5s)
  --threads    : concurrency for directory brute force (default 10)
  --no-nmap    : disable nmap even if installed
  --subenum    : attempt simple subdomain enumeration (optional)

Report files are saved into `reports/` (HTML + JSON).


## Features

- Target information gathering (DNS, HTTP headers, Whois)
- Network port scanning (Nmap & socket fallback)
- Service-based CVE vulnerability checking (using Vulners API)
- SSL/TLS certificate and protocol inspection
- Web directory brute forcing
- SQL Injection and Cross-Site Scripting (XSS) vulnerability testing
- Complete HTML report generation

## Requirements

- Python 3.8+
- Nmap tool installed on your system (Linux/Windows)
- Python packages:
  - requests
  - beautifulsoup4
  - python-whois
  - python-nmap
  - sslyze

## Installation

```bash
git clone https://github.com/yourusername/basic-vuln-scanner.git
cd basic-vuln-scanner
pip install -r requirements.txt
sudo apt install nmap
