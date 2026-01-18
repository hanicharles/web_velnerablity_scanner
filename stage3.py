import requests

def check_missing_headers_vuln(headers):
    vulns = []
    required_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': ['SAMEORIGIN', 'DENY'],
        'Strict-Transport-Security': None, # Just presence check
        'Content-Security-Policy': None
    }
    
    for h, expected in required_headers.items():
        if h not in headers:
            vulns.append(f"Missing Security Header: {h}")
        elif expected:
            val = headers[h]
            if isinstance(expected, list):
                if val not in expected:
                    pass # Loose check
            elif val != expected:
                pass 
                
    return vulns

def check_cookie_security(url):
    vulns = []
    try:
        response = requests.get(url, timeout=5)
        for cookie in response.cookies:
            if not cookie.secure:
                vulns.append(f"Cookie {cookie.name} missing Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                # Requests cookies don't expose HttpOnly easily in all versions, 
                # strictly speaking 'rest' has it but let's assume if it's not set.
                # Actually Requests CookieJar is tricky.
                # Better to check Set-Cookie header if possible.
                pass
                
        # Alternative: check Set-Cookie header
        if 'Set-Cookie' in response.headers:
            set_cookie = response.headers['Set-Cookie']
            if 'Secure' not in set_cookie:
                vulns.append("Set-Cookie header missing Secure flag")
            if 'HttpOnly' not in set_cookie:
                vulns.append("Set-Cookie header missing HttpOnly flag")
                
    except Exception as e:
        pass
    return vulns

def check_outdated_server(server_header):
    vulns = []
    if not server_header:
        return vulns
        
    server_header = server_header.lower()
    # Very basic heuristics
    if "apache/2.2" in server_header:
        vulns.append("Outdated Apache version (2.2) detected")
    if "nginx/1.14" in server_header: # Example
        vulns.append("Potentially outdated Nginx version")
    if "php/5" in server_header:
        vulns.append("Outdated PHP version 5 detected")
        
    return vulns

def run_stage3(url, headers):
    print(f"[*] Starting Stage 3: Vulnerability Assessment on {url}")
    vulnerabilities = []
    
    # 1. Missing Headers
    vulnerabilities.extend(check_missing_headers_vuln(headers))
    
    # 2. Cookie Security
    vulnerabilities.extend(check_cookie_security(url))
    
    # 3. Server Version
    if 'Server' in headers:
        vulnerabilities.extend(check_outdated_server(headers['Server']))
        
    return vulnerabilities
