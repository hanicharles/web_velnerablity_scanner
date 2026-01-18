import socket
import requests
import dns.resolver
import ssl
import subprocess
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def get_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def get_ip_address(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return f"Error: {e}"

def get_http_headers(url):
    try:
        response = requests.head(url, timeout=5)
        return response.headers
    except Exception as e:
        return f"Error: {e}"

def check_robots_txt(url):
    try:
        if not url.endswith('/'):
            url += '/'
        robots_url = url + "robots.txt"
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            return "Found"
        else:
            return "Not Found"
    except Exception as e:
        return f"Error: {e}"

def check_sitemap_xml(url):
    try:
        if not url.endswith('/'):
            url += '/'
        sitemap_url = url + "sitemap.xml"
        response = requests.get(sitemap_url, timeout=5)
        if response.status_code == 200:
            return "Found"
        else:
            return "Not Found"
    except Exception as e:
        return f"Error: {e}"

def dns_lookup(domain):
    records = {}
    try:
        # A Record
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            records['A'] = [r.to_text() for r in a_records]
        except:
            records['A'] = []
            
        # MX Record
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            records['MX'] = [r.to_text() for r in mx_records]
        except:
            records['MX'] = []
            
        return records
    except Exception as e:
        return f"Error: {e}"

def server_info(headers):
    if isinstance(headers, dict) or hasattr(headers, 'get'):
        return headers.get('Server', 'Unknown')
    return "No headers provided"

def ssl_certificate_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
        return cert
    except Exception as e:
        return f"Error: {e}"

def extract_links(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        return links[:10] # Return first 10 links to keep it brief
    except Exception as e:
        return f"Error: {e}"

def check_security_headers(headers):
    security_headers = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Strict-Transport-Security',
        'Content-Security-Policy'
    ]
    present_headers = {}
    if isinstance(headers, dict) or hasattr(headers, 'get'):
        for h in security_headers:
            present_headers[h] = headers.get(h, "Missing")
    return present_headers

def nmap_scan(ip):
    try:
        # Running a fast scan (-F)
        result = subprocess.run(['nmap', '-F', ip], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error: {e}"

def run_stage1(url):
    print(f"[*] Starting Stage 1: Reconnaissance on {url}")
    results = {}
    
    domain = get_domain(url)
    
    # 1. IP Address
    print("[+] Resolving IP...")
    ip = get_ip_address(domain)
    results['ip'] = ip
    
    # 2. DNS Lookup
    print("[+] Performing DNS Lookup...")
    results['dns'] = dns_lookup(domain)
    
    # 3. HTTP Headers
    print("[+] Fetching HTTP Headers...")
    headers = get_http_headers(url)
    results['headers'] = dict(headers) if hasattr(headers, 'items') else str(headers)
    
    # 4. Server Info
    print("[+] Extracting Server Info...")
    results['server_info'] = server_info(headers)
    
    # 5. Security Headers
    print("[+] Checking Security Headers...")
    results['security_headers'] = check_security_headers(headers)
    
    # 6. Robots.txt
    print("[+] Checking robots.txt...")
    results['robots_txt'] = check_robots_txt(url)
    
    # 7. Sitemap.xml
    print("[+] Checking sitemap.xml...")
    results['sitemap_xml'] = check_sitemap_xml(url)
    
    # 8. SSL Info
    print("[+] Getting SSL Info...")
    results['ssl_info'] = str(ssl_certificate_info(domain))[:200] + "..." # Truncate for brevity
    
    # 9. Extract Links
    print("[+] Extracting Links...")
    results['links'] = extract_links(url)
    
    # 10. Nmap Scan
    if ip and not ip.startswith("Error"):
        print("[+] Running Nmap Scan...")
        results['nmap'] = nmap_scan(ip)
    else:
        results['nmap'] = "Skipped (No IP)"
        
    return results
