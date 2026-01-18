import argparse
import sys
import os

# Allow running from inside the directory by adding parent to path
if __name__ == "__main__" and __package__ is None:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    sys.path.append(parent_dir)

from web_scanner.stage1 import run_stage1
from web_scanner.stage2 import run_stage2
from web_scanner.stage3 import run_stage3
from web_scanner.stage4 import run_stage4
from web_scanner.stage5 import run_stage5

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner with 5 Stages")
    parser.add_argument("url", help="Target URL (e.g., http://example.com)")
    args = parser.parse_args()
    
    target_url = args.url
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
        
    print(f"[*] Starting Scan on {target_url}")
    print("="*60)
    
    all_results = {'target': target_url}
    
    # Stage 1
    try:
        stage1_results = run_stage1(target_url)
        all_results['stage1'] = stage1_results
    except Exception as e:
        print(f"[-] Error in Stage 1: {e}")
        all_results['stage1'] = {'error': str(e)}

    print("-" * 60)

    # Stage 2
    try:
        ip = all_results.get('stage1', {}).get('ip')
        stage2_results = run_stage2(target_url, ip)
        all_results['stage2'] = stage2_results
    except Exception as e:
        print(f"[-] Error in Stage 2: {e}")
        all_results['stage2'] = {'error': str(e)}

    print("-" * 60)

    # Stage 3
    try:
        headers = all_results.get('stage1', {}).get('headers', {})
        stage3_results = run_stage3(target_url, headers)
        all_results['stage3'] = stage3_results
    except Exception as e:
        print(f"[-] Error in Stage 3: {e}")
        all_results['stage3'] = {'error': str(e)}

    print("-" * 60)

    # Stage 4
    try:
        stage4_results = run_stage4(target_url)
        all_results['stage4'] = stage4_results
    except Exception as e:
        print(f"[-] Error in Stage 4: {e}")
        all_results['stage4'] = {'error': str(e)}
        
    print("-" * 60)

    # Stage 5
    try:
        run_stage5(all_results)
    except Exception as e:
        print(f"[-] Error in Stage 5: {e}")

    print("="*60)
    print("[*] Scan Completed.")

if __name__ == "__main__":
    main()
