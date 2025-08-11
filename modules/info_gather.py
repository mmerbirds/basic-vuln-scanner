import socket
import requests
from bs4 import BeautifulSoup
import whois
import time

def get_info(target, timeout=5, subenum=False):
    info = {}
    try:
        ip = socket.gethostbyname(target)
        info['ip'] = ip
    except Exception as e:
        info['ip'] = f'Error resolving: {e}'

    # HTTP headers and CMS detection
    try:
        r = requests.get(f'http://{target}', timeout=timeout)
        info['http_headers'] = dict(r.headers)
        soup = BeautifulSoup(r.text, 'html.parser')
        gen = soup.find('meta', attrs={'name': 'generator'})
        if gen and gen.get('content'):
            info['cms'] = gen.get('content')
    except Exception:
        info['http_headers'] = {}

    # HTTPS check
    try:
        r2 = requests.get(f'https://{target}', timeout=timeout, verify=False)
        info['https'] = True
        info['https_headers'] = dict(r2.headers)
    except Exception:
        info['https'] = False

    # Whois info
    try:
        w = whois.whois(target)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        info['registered_on'] = str(created) if created else None
    except Exception:
        info['registered_on'] = None

    # Subdomain enumeration (basic)
    if subenum:
        subs = []
        common = ['www', 'mail', 'ftp', 'dev', 'test', 'staging']
        for s in common:
            try:
                ip_sub = socket.gethostbyname(f"{s}.{target}")
                subs.append({'subdomain': f"{s}.{target}", 'ip': ip_sub})
            except Exception:
                continue
        info['subdomains'] = subs

    info['timestamp'] = time.ctime()
    return info
