#!/usr/bin/env python3
"""
subdomain_takeover.py - Subdomain Takeover Scanner
Checks for dangling CNAME records pointing to unclaimed services.
"""
import dns.resolver
import json
import requests
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Common takeover signatures { "CNAME ending": "String to look for in response" }
SIGNATURES = {
    "github.io": "There isn't a GitHub Pages site here.",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "corewindows.net": "NoSuchAccount",
    "azurewebsites.net": "404 Web Site not found",
    "bitbucket.io": "Repository not found",
    "readme.io": "Project doesnt exist",
    "ghost.io": "The thing you were looking for is no longer here",
    "shopify.com": "Sorry, this shop is currently unavailable.",
    "surge.sh": "project not found",
    "webflow.io": "The page you are looking for doesn't exist or has been moved",
    "helpscoutdocs.com": "No Desk Found",
    "cargocollective.com": "404 Not Found",
    "tumblr.com": "Whatever you were looking for doesn't currently exist at this address.",
    "wpengine.com": "The site you were looking for couldn't be found.",
}

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'-'*12}[ {title} ]{'-'*12}{Style.RESET_ALL}")

def ok(msg):      print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):     print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def info(msg):    print(f"{Fore.BLUE}[>]{Style.RESET_ALL} {msg}")

def process(domain):
    banner("Subdomain Takeover Scan")
    info(f"Target: {domain}")
    
    # We will check the main domain and typical subdomains.
    subdomains_to_check = [
        domain,
        f"www.{domain}",
        f"blog.{domain}",
        f"docs.{domain}",
        f"support.{domain}",
        f"help.{domain}",
        f"api.{domain}",
        f"dev.{domain}",
        f"test.{domain}",
        f"staging.{domain}"
    ]
    
    output = {
        "domain": domain,
        "vulnerable": [],
        "safe": [],
        "scanned_at": datetime.now().isoformat()
    }
    
    for sub in subdomains_to_check:
        try:
            answers = dns.resolver.resolve(sub, 'CNAME', lifetime=5)
            for rdata in answers:
                cname = str(rdata).rstrip('.')
                matched_service = next((srv for srv in SIGNATURES if cname.endswith(srv)), None)
                
                if matched_service:
                    info(f"{sub} -> {cname} (Potential {matched_service} takeover)")
                    try:
                        r = requests.get(f"http://{sub}", timeout=5)
                        if SIGNATURES[matched_service] in r.text:
                            err(f"VULNERABLE: {sub} -> {cname}")
                            output["vulnerable"].append({
                                "subdomain": sub,
                                "cname": cname,
                                "service": matched_service,
                                "evidence": SIGNATURES[matched_service]
                            })
                        else:
                            ok(f"SAFE: {sub} -> {cname} (Service claimed)")
                            output["safe"].append({"subdomain": sub, "cname": cname, "status": "Claimed"})
                    except Exception as e:
                        warn(f"Could not verify {sub}: {e}")
                else:
                    output["safe"].append({"subdomain": sub, "cname": cname, "status": "No known signatures"})
        except Exception:
            pass
            
    if not output["vulnerable"]:
        ok("No subdomain takeovers detected among common subdomains.")
        
    return output

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    print(json.dumps(process(domain), indent=2))


