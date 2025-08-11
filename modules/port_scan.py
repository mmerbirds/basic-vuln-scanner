import shutil
import socket

def scan_ports(target, ports_range='20-1024', use_nmap=True):
    results = []
    try:
        if use_nmap and shutil.which('nmap'):
            import nmap
            nm = nmap.PortScanner()
            print('[*] Running nmap scan...')
            nm.scan(target, ports_range)
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        state = nm[host][proto][port]['state']
                        name = nm[host][proto][port].get('name', '')
                        product = nm[host][proto][port].get('product', '')
                        version = nm[host][proto][port].get('version', '')
                        results.append({
                            'port': port,
                            'state': state,
                            'proto': proto,
                            'name': name,
                            'product': product,
                            'version': version
                        })
            return results
    except Exception as e:
        print('[!] nmap scan failed:', e)

    # fallback: socket scan
    print('[*] Running socket scan fallback...')
    common_ports = [21,22,23,25,53,67,68,80,110,111,135,137,139,143,161,162,443,445,3306,8080,8443]
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            res = sock.connect_ex((target, port))
            state = 'open' if res == 0 else 'closed'
            results.append({'port': port, 'state': state, 'proto': 'tcp'})
            sock.close()
        except Exception:
            results.append({'port': port, 'state': 'unknown', 'proto': 'tcp'})
    return results
