#!/usr/bin/env python3
"""
breach.py - Email Breach Checker
Uses XposedOrNot free API to check for email data breaches.
"""
import requests
import json
import sys
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'-'*12}[ {title} ]{'-'*12}{Style.RESET_ALL}")

def ok(msg):      print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):     print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def info(msg):    print(f"{Fore.BLUE}[>]{Style.RESET_ALL} {msg}")

def check_xposedornot(email):
    """Uses the free XposedOrNot API to check for email breaches."""
    try:
        r = requests.get(f"https://api.xposedornot.com/v1/check-email/{email}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            breaches = data.get("breaches", [[]])[0]
            return {"breached": True, "breaches": breaches}
        elif r.status_code == 404:
            return {"breached": False, "breaches": []}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def process(domain):
    banner("Email Breach Check")
    info(f"Target Domain: {domain}")
    
    # Normally this takes emails found in scrapping.py
    # We will check a few common admin emails and generic ones for the domain
    emails_to_check = [
        f"admin@{domain}",
        f"info@{domain}",
        f"contact@{domain}",
        f"support@{domain}",
        f"hr@{domain}",
        f"sales@{domain}"
    ]
    
    output = {
        "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "emails_checked": len(emails_to_check),
        "breaches_found": []
    }
    
    for email in emails_to_check:
        info(f"Checking {email}...")
        res = check_xposedornot(email)
        time.sleep(1) # respectful delay to avoid rate limiting
        
        if res.get("breached"):
            err(f"BREACHED: {email} found in {len(res['breaches'])} breaches")
            output["breaches_found"].append({
                "email": email,
                "breaches": res["breaches"]
            })
            for b in res["breaches"][:3]:
                print(f"    - {b}")
        elif res.get("error"):
            warn(f"Error checking {email}: {res['error']}")
        else:
            ok(f"SAFE: {email} (no known breaches)")
            
    return output

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    print(json.dumps(process(domain), indent=2))


