#!/usr/bin/env python3
import subprocess
import re
from colorama import Fore, Style, init

# ----------------------------
# Initialize colorama
# ----------------------------
init(autoreset=True)

# ----------------------------
# Constants
# ----------------------------
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

# Color shortcuts for easier styling
COLOR_TITLE = Fore.CYAN + Style.BRIGHT
COLOR_INFO = Fore.YELLOW + Style.BRIGHT
COLOR_SUCCESS = Fore.GREEN + Style.BRIGHT
COLOR_WARN = Fore.MAGENTA + Style.BRIGHT
COLOR_ERROR = Fore.RED + Style.BRIGHT
COLOR_HIGHLIGHT = Fore.LIGHTBLUE_EX + Style.BRIGHT

# ----------------------------
# TheHarvester Integration
# ----------------------------
def run_theharvester(domain):
    """Run TheHarvester to scrape emails for a given domain"""
    print(COLOR_INFO + f"[*] Launching TheHarvester for domain: {COLOR_HIGHLIGHT}{domain}")
    import shutil
    if not shutil.which("theHarvester"):
        print(COLOR_WARN + "[!] TheHarvester not found in PATH. Skipping.")
        return set()
    try:
        cmd = [
            "theHarvester", "-d", domain,
            "-b", "bing,duckduckgo,yahoo,crtsh,threatcrowd,hackertarget,github-code"
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, shell=True
        )
        output = result.stdout + result.stderr
        emails = re.findall(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", output)
        return set(emails)
    except subprocess.TimeoutExpired:
        print(COLOR_WARN + "[!] TheHarvester timed out after 120s.")
        return set()
    except Exception as e:
        print(COLOR_ERROR + f"[!] TheHarvester encountered an error: {e}")
        return set()

# ----------------------------
# Pretty Print Helper
# ----------------------------
def pretty_print(result):
    domain = result.get("domain", "Unknown")
    emails = result.get("emails", [])

    # Header
    print("\n" + COLOR_TITLE + "="*60)
    print(COLOR_TITLE + f"  Email Scan Results for Domain: {COLOR_HIGHLIGHT}{domain}")
    print(COLOR_TITLE + "="*60 + "\n")

    # Emails
    if emails:
        print(COLOR_SUCCESS + f"[+] Emails Found: {len(emails)}\n")
        for idx, email in enumerate(emails, start=1):
            print(f"   {COLOR_HIGHLIGHT}{idx}. {email}")
        print()
    else:
        print(COLOR_WARN + "[!] No emails were found.\n")

    # Footer
    print(COLOR_TITLE + "="*60 + "\n")

# ----------------------------
# Pipeline Entry Point
# ----------------------------
def process(domain: str):
    print(COLOR_INFO + f"[*] Processing domain: {COLOR_HIGHLIGHT}{domain}\n")
    
    all_emails = run_theharvester(domain)

    result = {
        "domain": domain,
        "emails": sorted(list(all_emails)),
    }

    pretty_print(result)
    return result

# ----------------------------
# Standalone test
# ----------------------------
if __name__ == "__main__":
    test_domain = "example.com"
    res = process(test_domain)
    print(COLOR_INFO + "Result Dictionary:")
    print(res)
