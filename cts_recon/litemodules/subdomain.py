#!/usr/bin/env python3
import subprocess
from colorama import Fore, Style, init

# ----------------------------
# Initialize Colorama
# ----------------------------
init(autoreset=True)

# ----------------------------
# Color Definitions
# ----------------------------
COLOR_TITLE = Fore.CYAN + Style.BRIGHT
COLOR_INFO = Fore.YELLOW + Style.BRIGHT
COLOR_SUCCESS = Fore.GREEN + Style.BRIGHT
COLOR_WARN = Fore.MAGENTA + Style.BRIGHT
COLOR_ERROR = Fore.RED + Style.BRIGHT
COLOR_HIGHLIGHT = Fore.LIGHTBLUE_EX + Style.BRIGHT

# ----------------------------
# Helper: Probe Alive Domains
# ----------------------------
def probe_alive(domain):
    """Find alive domains using subfinder + httpx"""
    alive = []
    try:
        print(COLOR_INFO + f"[*] Running subfinder + httpx for {COLOR_HIGHLIGHT}{domain}...")
        # Use simple pipe for Windows, ensure tools are in PATH
        cmd = f"subfinder -d {domain} -silent | httpx -silent"
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
             errors='ignore' # Handle potential encoding issues
        )
        alive = result.stdout.splitlines()
    except Exception as e:
        print(COLOR_ERROR + f"[!] Error running subfinder/httpx: {e}")
    return alive

# ----------------------------
# Pretty Print Alive Hosts
# ----------------------------
def pretty_print_alive(domain, alive_hosts):
    print("\n" + COLOR_TITLE + "="*60)
    print(COLOR_TITLE + f"  Alive Hosts Scan Results for: {COLOR_HIGHLIGHT}{domain}")
    print(COLOR_TITLE + "="*60 + "\n")

    if alive_hosts:
        print(COLOR_SUCCESS + f"[✓] Found {len(alive_hosts)} alive hosts:\n")
        for idx, host in enumerate(alive_hosts, start=1):
            print(f"   {COLOR_HIGHLIGHT}{idx}. {host}")
    else:
        print(COLOR_WARN + "[!] No alive hosts found.")

    print("\n" + COLOR_TITLE + "="*60 + "\n")

# ----------------------------
# Pipeline-Compatible Entry
# ----------------------------
def process(domain):
    """Executed by pipeline.py to scan alive hosts"""
    alive_hosts = probe_alive(domain)
    pretty_print_alive(domain, alive_hosts)
    return {"alive": alive_hosts}

# ----------------------------
# Example Standalone Usage
# ----------------------------
if __name__ == "__main__":
    test_domain = "example.com"
    result = process(test_domain)
    print(COLOR_INFO + "JSON Output:")
    print(result)
