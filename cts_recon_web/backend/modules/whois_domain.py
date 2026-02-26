#!/usr/bin/env python3
"""
whois_domain.py - Domain WHOIS Information
Retrieves WHOIS data (registrar, creation date, expiry date)
Install: pip install python-whois
"""
import json
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'-'*12}[ {title} ]{'-'*12}{Style.RESET_ALL}")

def ok(msg):      print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):     print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def info(msg):    print(f"{Fore.BLUE}[>]{Style.RESET_ALL} {msg}")

def format_date(date_obj):
    if isinstance(date_obj, list):
        return [d.isoformat() if hasattr(d, 'isoformat') else str(d) for d in date_obj]
    if hasattr(date_obj, 'isoformat'):
        return date_obj.isoformat()
    return str(date_obj)

def process(domain):
    banner("WHOIS Information")
    info(f"Target: {domain}")
    
    output = {
        "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "success": False,
        "data": {}
    }
    
    if not HAS_WHOIS:
        warn("python-whois not installed. Run: pip install python-whois")
        output["error"] = "python-whois not installed"
        return output
        
    try:
        w = whois.whois(domain)
        output["success"] = True
        
        data = {
            "registrar": w.registrar,
            "whois_server": w.whois_server,
            "creation_date": format_date(w.creation_date),
            "expiration_date": format_date(w.expiration_date),
            "updated_date": format_date(w.updated_date),
            "name_servers": w.name_servers,
            "emails": w.emails,
            "org": w.org
        }
        output["data"] = data
        
        ok(f"Registrar: {data['registrar']}")
        if data['creation_date']:
            info(f"Created: {data['creation_date']}")
        if data['expiration_date']:
            info(f"Expires: {data['expiration_date']}")
        if data['name_servers']:
            ns_str = ', '.join(data['name_servers']) if isinstance(data['name_servers'], list) else data['name_servers']
            info(f"Name Servers: {ns_str}")
            
    except Exception as e:
        err(f"WHOIS lookup failed: {e}")
        output["error"] = str(e)
        
    return output

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    print(json.dumps(process(domain), indent=2))


