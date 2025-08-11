import os
from datetime import datetime

def generate_report(target, info, ports, cve_results, ssl_results, sqli, xss, found_dirs, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{target}_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"<html><head><title>Scan Report for {target}</title></head><body>")
        f.write(f"<h1>Scan Report for {target}</h1>")
        f.write(f"<h2>Scan Time: {datetime.now()}</h2>")

        # Info Gathering
        f.write("<h3>1. Target Info</h3><ul>")
        for k,v in info.items():
            f.write(f"<li><b>{k}</b>: {v}</li>")
        f.write("</ul>")

        # Port scan results
        f.write("<h3>2. Port Scan Results</h3><table border='1'><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>")
        for port in ports:
            f.write(f"<tr><td>{port.get('port')}</td><td>{port.get('state')}</td><td>{port.get('product','')}</td><td>{port.get('version','')}</td></tr>")
        f.write("</table>")

        # CVE Results
        f.write("<h3>3. CVE Results</h3>")
        if cve_results:
            for cr in cve_results:
                f.write(f"<h4>Port {cr['port']} - {cr['service']} {cr['version']}</h4><ul>")
                for cve in cr['cves']:
                    f.write(f"<li><b>{cve.get('title')}</b> - CVSS: {cve.get('cvss', {}).get('score', 'N/A')}<br>{cve.get('description','')}</li>")
                f.write("</ul>")
        else:
            f.write("<p>No known CVEs found.</p>")

        # SSL Results
        f.write("<h3>4. SSL/TLS Scan Results</h3>")
        if 'error' in ssl_results:
            f.write(f"<p>Error: {ssl_results['error']}</p>")
        else:
            cert = ssl_results.get("certificate")
            if cert:
                f.write("<b>Certificate Info:</b><ul>")
                for key, val in cert.items():
                    f.write(f"<li>{key}: {val}</li>")
                f.write("</ul>")
            f.write(f"<b>Supported Protocols:</b> {', '.join(ssl_results.get('protocols', []))}<br>")
            if ssl_results.get('weak_protocols'):
                f.write(f"<b>Weak Protocols:</b> {', '.join(ssl_results.get('weak_protocols', []))}<br>")
            if ssl_results.get('issues'):
                f.write(f"<b>Issues Found:</b><ul>")
                for issue in ssl_results['issues']:
                    f.write(f"<li>{issue}</li>")
                f.write("</ul>")
        # SQLi
        f.write("<h3>5. SQL Injection Test</h3>")
        f.write(f"<p>{'Vulnerable' if sqli else 'No vulnerabilities found.'}</p>")
        # XSS
        f.write("<h3>6. XSS Test</h3>")
        f.write(f"<p>{'Vulnerable' if xss else 'No vulnerabilities found.'}</p>")
        # Directory Bruteforce
        f.write("<h3>7. Directory Brute Force Results</h3><ul>")
        for d in found_dirs:
            f.write(f"<li>{d['url']} (Status: {d['status']})</li>")
        f.write("</ul>")

        f.write("</body></html>")
    return filepath
