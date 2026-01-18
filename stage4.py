import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def check_xss(url):
    print("[*] Checking for Reflected XSS...")
    payload = "<script>alert('XSS')</script>"
    # Try appending payload as a parameter
    test_params = {'q': payload, 'search': payload, 'id': payload}
    
    potential_xss = []
    
    # 1. Test common parameters
    try:
        response = requests.get(url, params=test_params, timeout=5)
        if payload in response.text:
            potential_xss.append(f"Reflected XSS found with common params on {url}")
    except:
        pass

    # 2. Test existing parameters
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if params:
        for param in params:
            new_params = params.copy()
            new_params[param] = payload
            query = urlencode(new_params, doseq=True)
            new_url = urlunparse(parsed._replace(query=query))
            try:
                response = requests.get(new_url, timeout=5)
                if payload in response.text:
                    potential_xss.append(f"Reflected XSS found in parameter '{param}'")
            except:
                pass
                
    return potential_xss

def check_sqli(url):
    print("[*] Checking for SQL Injection (Error-based)...")
    payloads = ["'", "\"", " OR 1=1", "' OR '1'='1"]
    errors = ["SQL syntax", "mysql_fetch", "syntax error", "ORA-", "PostgreSQL error"]
    
    potential_sqli = []
    
    # Check existing parameters
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        # If no params, maybe append one?
        return []
        
    for param in params:
        for payload in payloads:
            new_params = params.copy()
            new_params[param] = [val + payload for val in new_params[param]]
            query = urlencode(new_params, doseq=True)
            new_url = urlunparse(parsed._replace(query=query))
            try:
                response = requests.get(new_url, timeout=5)
                for error in errors:
                    if error.lower() in response.text.lower():
                        potential_sqli.append(f"Potential SQLi in '{param}' with payload '{payload}'")
                        break
            except:
                pass
                
    return potential_sqli

def run_stage4(url):
    print(f"[*] Starting Stage 4: Exploitation (POC) on {url}")
    results = {}
    
    results['xss'] = check_xss(url)
    results['sqli'] = check_sqli(url)
    
    return results
