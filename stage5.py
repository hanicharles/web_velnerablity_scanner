import json
import datetime

def generate_report(results, filename="scan_report"):
    print("[*] Generating Report...")
    
    # Add timestamp
    results['timestamp'] = datetime.datetime.now().isoformat()
    
    # JSON Report
    json_filename = f"{filename}.json"
    try:
        with open(json_filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[+] JSON report saved to {json_filename}")
    except Exception as e:
        print(f"[-] Error saving JSON report: {e}")

    # Text Report
    txt_filename = f"{filename}.txt"
    try:
        with open(txt_filename, 'w') as f:
            f.write("Web Vulnerability Scan Report\n")
            f.write("==============================\n")
            f.write(f"Target: {results.get('target', 'Unknown')}\n")
            f.write(f"Timestamp: {results['timestamp']}\n\n")
            
            f.write("Stage 1: Reconnaissance\n")
            f.write("-----------------------\n")
            stage1 = results.get('stage1', {})
            for k, v in stage1.items():
                f.write(f"{k}: {v}\n")
            f.write("\n")
            
            f.write("Stage 2: Scanning & Enumeration\n")
            f.write("-------------------------------\n")
            stage2 = results.get('stage2', {})
            for k, v in stage2.items():
                f.write(f"{k}: {v}\n")
            f.write("\n")
            
            f.write("Stage 3: Vulnerability Assessment\n")
            f.write("---------------------------------\n")
            stage3 = results.get('stage3', [])
            if stage3:
                for v in stage3:
                    f.write(f"[!] {v}\n")
            else:
                f.write("No obvious vulnerabilities found in this stage.\n")
            f.write("\n")
            
            f.write("Stage 4: Exploitation POC\n")
            f.write("-------------------------\n")
            stage4 = results.get('stage4', {})
            for k, v in stage4.items():
                if v:
                    for item in v:
                        f.write(f"[!!] {item}\n")
                else:
                    f.write(f"{k}: No issues found.\n")
            f.write("\n")
            
        print(f"[+] Text report saved to {txt_filename}")
    except Exception as e:
        print(f"[-] Error saving text report: {e}")

def run_stage5(results):
    generate_report(results)
