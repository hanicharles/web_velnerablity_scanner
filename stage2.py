import socket
import requests
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        s.close()
        if result == 0:
            return port
    except:
        pass
    return None

def port_scan(target_ip, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]
    
    print(f"[*] Scanning {len(ports)} ports on {target_ip}...")
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(scan_port, target_ip, port) for port in ports]
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

def check_path(url, path):
    try:
        if not url.endswith('/'):
            url += '/'
        full_url = url + path
        response = requests.get(full_url, timeout=3, allow_redirects=False)
        if response.status_code == 200:
            return path
    except:
        pass
    return None

def directory_enumeration(url):
    paths_to_check = [
        "admin", "login", "dashboard", "uploads", "images", "css", "js", 
        "config", "backup", "db", "api", ".git", ".env", "wp-admin", 
        "robots.txt", "sitemap.xml"
    ]
    
    print(f"[*] Enumerating directories on {url}...")
    found_paths = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_path, url, path) for path in paths_to_check]
        for future in futures:
            result = future.result()
            if result:
                found_paths.append(result)
    return found_paths

def run_stage2(url, ip):
    print(f"[*] Starting Stage 2: Scanning & Enumeration on {url}")
    results = {}
    
    # Port Scan
    if ip and not ip.startswith("Error"):
        results['open_ports'] = port_scan(ip)
    else:
        results['open_ports'] = "Skipped (No IP)"
        
    # Directory Enumeration
    results['directories'] = directory_enumeration(url)
    
    return results
