import requests
from concurrent.futures import ThreadPoolExecutor

def check_url(url, timeout=5):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False)
        if r.status_code in [200, 301, 302]:
            return url, r.status_code
    except:
        pass
    return None, None

def brute_dirs(target, wordlist_path="wordlists/dirs.txt", threads=10, timeout=5):
    found = []
    if not target.startswith("http"):
        target = "http://" + target
    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f.readlines()]
    urls = [f"{target}/{w}" for w in words]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_url, url, timeout) for url in urls]
        for future in futures:
            url, status = future.result()
            if url and status:
                found.append({'url': url, 'status': status})
    return found
