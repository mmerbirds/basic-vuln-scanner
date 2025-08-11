#!/usr/bin/env python3
import argparse
import os
from modules import (
    info_gather,
    port_scan,
    cve_lookup,
    ssl_scan,
    dir_bruteforce,
    vuln_tests,
    report
)

def main():
    parser = argparse.ArgumentParser(description="Advanced Basic Vulnerability Scanner")
    parser.add_argument("target", help="Target domain or IP (e.g., example.com)")
    parser.add_argument("--output", default="reports", help="Output folder")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout seconds")
    parser.add_argument("--threads", type=int, default=10, help="Concurrency for brute force")
    parser.add_argument("--no-nmap", action="store_true", help="Disable nmap usage")
    parser.add_argument("--subenum", action="store_true", help="Run simple subdomain enumeration")
    parser.add_argument("--vulners-api-key", default=None, help="API key for Vulners CVE lookup (optional)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    target = args.target
    print(f"[*] Starting scan on target: {target}")

    # 1. Info Gathering
    print("[*] Gathering target info...")
    info = info_gather.get_info(target, timeout=args.timeout, subenum=args.subenum)

    # 2. Port Scanning
    print("[*] Scanning ports and services...")
    ports = port_scan.scan_ports(target, use_nmap=not args.no_nmap)

    # 3. CVE Lookup
    print("[*] Checking for known vulnerabilities (CVE)...")
    cve_results = []
    for port in ports:
        if port.get('state') == 'open' and port.get('product'):
            service = port.get('product')
            version = port.get('version', '')
            if service:
                cves = cve_lookup.search_cve(service, version, api_key=args.vulners_api_key)
                if cves:
                    cve_results.append({
                        'port': port['port'],
                        'service': service,
                        'version': version,
                        'cves': cves
                    })

    # 4. SSL/TLS Scan
    print("[*] Performing SSL/TLS security scan...")
    ssl_results = ssl_scan.scan_ssl(target)

    # 5. Directory Bruteforce
    print("[*] Performing directory brute force...")
    found_dirs = dir_bruteforce.brute_dirs(target, wordlist_path="wordlists/dirs.txt", threads=args.threads, timeout=args.timeout)

    # 6. Vulnerability Tests (SQLi & XSS)
    print("[*] Testing for SQL Injection vulnerabilities...")
    sqli = vuln_tests.check_sqli(target, timeout=args.timeout)

    print("[*] Testing for Cross-Site Scripting (XSS) vulnerabilities...")
    xss = vuln_tests.check_xss(target, timeout=args.timeout)

    # 7. Generate Report
    print("[*] Generating report...")
    report_path = report.generate_report(
        target,
        info,
        ports,
        cve_results,
        ssl_results,
        sqli,
        xss,
        found_dirs,
        output_dir=args.output
    )

    print(f"[+] Scan complete. Report saved at: {report_path}")

if __name__ == '__main__':
    main()