#!/usr/bin/env python3
import subprocess
import re
from datetime import datetime
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
# DNS + WHOIS Helpers
# ----------------------------
def get_dns_records(domain):
    try:
        # Use nslookup as dig is not standard on Windows
        result = subprocess.run(
            ["nslookup", domain],
            capture_output=True, text=True, check=True
        )
        # Parse nslookup output (basic)
        ips = []
        for line in result.stdout.splitlines():
             if "Address:" in line:
                 parts = line.split(":")
                 if len(parts) > 1:
                     ip = parts[1].strip()
                     # Filter out local DNS server IP usually printed first
                     if not ip.startswith("192.168") and not ip.startswith("127.") and not ip.startswith("10."):
                        ips.append(ip)
        return list(set(ips))
    except Exception:
        return []

def get_whois_info(ip):
    info = []
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if re.search(r"NetRange|CIDR|route", line, re.IGNORECASE):
                info.append(line.strip())
    except Exception as e:
        info.append(f"WHOIS lookup failed: {e}")
    return info

# ----------------------------
# Pretty Print DNS + WHOIS
# ----------------------------
def pretty_print_dns_whois(domain, dns_data, whois_data):
    print("\n" + COLOR_TITLE + "="*60)
    print(COLOR_TITLE + f"  DNS + WHOIS Scan Results for: {COLOR_HIGHLIGHT}{domain}")
    print(COLOR_TITLE + "="*60 + "\n")

    # DNS Records
    if dns_data:
        print(COLOR_SUCCESS + "[✓] DNS A Records:")
        for ip in dns_data:
            print(f"   {COLOR_HIGHLIGHT}{ip}")
    else:
        print(COLOR_WARN + "[!] No DNS A records found.")
    print()

    # WHOIS Records
    if whois_data:
        print(COLOR_SUCCESS + "[✓] WHOIS Information:")
        for entry in whois_data:
            ip = entry.get("ip", "Unknown")
            info = entry.get("whois", [])
            if info:
                print(f"   {COLOR_HIGHLIGHT}{ip}: {COLOR_INFO}{', '.join(info[:3])} ...")
            else:
                print(f"   {COLOR_HIGHLIGHT}{ip}: {COLOR_WARN}No WHOIS info found")
    print("\n" + COLOR_TITLE + "="*60 + "\n")

# ----------------------------
# Main Scan Function
# ----------------------------
def dns_whois_scan(domain):
    timestamp = datetime.now().isoformat()
    full_data = {"timestamp": timestamp, "domain": domain}

    print(COLOR_INFO + f"[*] Resolving DNS records for {COLOR_HIGHLIGHT}{domain}...")
    ips = get_dns_records(domain)
    full_data["dns"] = ips

    whois_results = []
    for ip in ips:
        info = get_whois_info(ip)
        whois_results.append({"ip": ip, "whois": info})
    full_data["whois"] = whois_results

    pretty_print_dns_whois(domain, ips, whois_results)
    print(COLOR_INFO + f"[*] DNS + WHOIS scan completed for {COLOR_HIGHLIGHT}{domain}\n")
    return full_data

# ----------------------------
# Pipeline-compatible function
# ----------------------------
def process(domain):
    return dns_whois_scan(domain)

# ----------------------------
# Example Usage
# ----------------------------
if __name__ == "__main__":
    target_domain = "evil.com"
    res = process(target_domain)
    print(COLOR_INFO + "Result Dictionary:")
    print(res)
