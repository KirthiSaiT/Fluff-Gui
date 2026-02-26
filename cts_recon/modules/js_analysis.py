#!/usr/bin/env python3
"""
js_analysis.py - JavaScript Static Analysis
Finds endpoints, secrets, and sensitive tokens inside common JS files.
"""
import requests
import re
import json
import sys
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style, init
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# Regex for common API endpoints and secrets
ENDPOINTS_REGEX = re.compile(
    r'(?:"|\')(((?:[a-zA-Z]{1,10}://|/)[^"\'\s]+)(?:[a-zA-Z0-9_.-]+))(?:"|\')'
)

SECRETS_REGEX = {
    "google_api": r'AIza[0-9A-Za-z\-_]{35}',
    "stripe": r'(?:sk|pk)_(live|test)_[0-9a-zA-Z]{24,}',
    "github_token": r'ghp_[0-9a-zA-Z]{36}',
    "slack_webhook": r'https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+',
    "aws_access_key": r'AKIA[0-9A-Z]{16}',
    "firebase": r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    "jwt": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
}

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'-'*12}[ {title} ]{'-'*12}{Style.RESET_ALL}")

def ok(msg):      print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):     print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def info(msg):    print(f"{Fore.BLUE}[>]{Style.RESET_ALL} {msg}")

def extract_js_links(url):
    try:
        r = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        js_files = []
        for script in soup.find_all('script'):
            if script.get('src'):
                js_files.append(urljoin(url, script.get('src')))
        return list(set(js_files))
    except Exception as e:
        warn(f"Failed to fetch {url}: {e}")
        return []

def analyze_js(js_url):
    results = {"endpoints": [], "secrets": []}
    try:
        r = requests.get(js_url, timeout=10, verify=False)
        content = r.text
        
        # Endpoints
        for match in ENDPOINTS_REGEX.findall(content):
            ep = match[0]
            if len(ep) > 5 and not ep.endswith(('.js', '.css', '.png', '.jpg', '.svg')):
                results["endpoints"].append(ep)
                
        # Secrets
        for name, regex in SECRETS_REGEX.items():
            for match in re.findall(regex, content):
                m = match if isinstance(match, str) else match[0]
                results["secrets"].append({"type": name, "value": m})
                
        results["endpoints"] = list(set(results["endpoints"]))
        
        # De-duplicate secrets
        seen = set()
        unique_secrets = []
        for s in results["secrets"]:
            if s["value"] not in seen:
                seen.add(s["value"])
                unique_secrets.append(s)
        results["secrets"] = unique_secrets
        
    except Exception:
        pass
        
    return results

def process(domain):
    banner("JavaScript Analysis")
    url = f"https://{domain}"
    info(f"Target: {url}")
    
    output = {
        "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "js_files_analyzed": 0,
        "findings": []
    }
    
    js_files = extract_js_links(url)
    ok(f"Found {len(js_files)} JavaScript files.")
    
    # Analyze up to 20 JS files to avoid taking too long
    for js_url in js_files[:20]:
        info(f"Analyzing {js_url}...")
        res = analyze_js(js_url)
        if res["endpoints"] or res["secrets"]:
            output["findings"].append({
                "url": js_url,
                "endpoints": res["endpoints"][:20], # limit to 20 endpoints per file
                "secrets": res["secrets"]
            })
            if res["secrets"]:
                for sec in res["secrets"]:
                    err(f"Secret found [{sec['type']}]: {sec['value'][:30]}...")
            ok(f"Extracted {len(res['endpoints'])} endpoints")
            
    output["js_files_analyzed"] = len(js_files[:20])
    return output

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    print(json.dumps(process(domain), indent=2))


