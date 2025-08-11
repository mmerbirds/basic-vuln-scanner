import requests

VULNERS_API_URL = "https://vulners.com/api/v3/search/lucene/"

def search_cve(service_name, version, api_key=None):
    query = f"{service_name} {version}"
    headers = {}
    if api_key:
        headers["X-Api-Key"] = api_key

    params = {
        "query": query,
        "size": 5,
        "sort": "cvss.score desc"
    }

    try:
        response = requests.get(VULNERS_API_URL, headers=headers, params=params, timeout=5)
        data = response.json()
        if data.get("data") and data["data"].get("documents"):
            return data["data"]["documents"]
    except Exception as e:
        print(f"[!] CVE lookup error: {e}")
    return []
