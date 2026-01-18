# Web Vulnerability Scanner

A Python-based web vulnerability scanner that performs security checks in 5 stages.

## Features

The scanner operates in the following stages:

1.  **Reconnaissance**: Gathers initial information using 10 distinct tools:
    *   IP Address Resolution
    *   DNS Lookup
    *   HTTP Headers Analysis
    *   Server Information Extraction
    *   Security Headers Check
    *   Robots.txt Check
    *   Sitemap.xml Check
    *   SSL Certificate Info
    *   Link Extraction
    *   Nmap Port Scan (requires Nmap installed)

2.  **Scanning & Enumeration**:
    *   Port Scanning (Top common ports)
    *   Directory Enumeration (Common paths like /admin, /login)

3.  **Vulnerability Assessment**:
    *   Checks for missing security headers (X-XSS-Protection, etc.)
    *   Checks for insecure cookies
    *   Checks for potentially outdated server versions

4.  **Exploitation (POC)**:
    *   Basic Reflected XSS tests
    *   Basic Error-based SQL Injection tests

5.  **Reporting**:
    *   Generates `scan_report.json` and `scan_report.txt` with findings.

## Installation

1.  **Prerequisites**:
    *   Python 3.x
    *   [Nmap](https://nmap.org/download.html) (for Stage 1 port scanning)

2.  **Install Dependencies**:
    Navigate to the project root or `web_scanner` directory and run:
    ```bash
    pip install -r web_scanner/requirements.txt
    ```

## Usage

You can run the scanner in two ways:

### 1. From the Repository Root (Recommended)

Run as a Python module:

```bash
python3 -m web_scanner.scanner <target_url>
```

**Example:**
```bash
python3 -m web_scanner.scanner http://example.com
```

### 2. From Inside the `web_scanner` Directory

Run directly as a script:

```bash
cd web_scanner
python3 scanner.py <target_url>
```

## Output

The tool will display progress in the console and save results to:
*   `scan_report.json`
*   `scan_report.txt`
