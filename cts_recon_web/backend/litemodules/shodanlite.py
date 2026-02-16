#!/usr/bin/env python3
import shodan
from colorama import Fore, Style, init

# ----------------------------
# Initialize Colorama
# ----------------------------
init(autoreset=True)

# ----------------------------
# Colors
# ----------------------------
COLOR_TITLE = Fore.CYAN + Style.BRIGHT
COLOR_INFO = Fore.YELLOW + Style.BRIGHT
COLOR_SUCCESS = Fore.GREEN + Style.BRIGHT
COLOR_WARN = Fore.MAGENTA + Style.BRIGHT
COLOR_ERROR = Fore.RED + Style.BRIGHT
COLOR_HIGHLIGHT = Fore.LIGHTBLUE_EX + Style.BRIGHT

# ----------------------------
# Shodan Setup
# ----------------------------
# ----------------------------
# Shodan Setup
# ----------------------------
# Using key from main project config
SHODAN_API_KEY = "M0T9JO1ZIgAqChRrUUVEKE1sLxz71vXr"
api = shodan.Shodan(SHODAN_API_KEY)

# ----------------------------
# Pretty Print Helper
# ----------------------------
def pretty_print_shodan(domain, shodan_data):
    print("\n" + COLOR_TITLE + "="*60)
    print(COLOR_TITLE + f"  Shodan Scan Results for: {COLOR_HIGHLIGHT}{domain}")
    print(COLOR_TITLE + "="*60 + "\n")

    if not shodan_data:
        print(COLOR_WARN + "[!] No results found on Shodan.\n")
        return

    for idx, entry in enumerate(shodan_data, start=1):
        ip = entry.get("ip", "N/A")
        port = entry.get("port", "N/A")
        org = entry.get("org", "N/A")
        vulns = entry.get("vulnerabilities", [])
        vuln_text = ", ".join(vulns) if vulns else "None"
        print(f"[{COLOR_HIGHLIGHT}{idx}{COLOR_TITLE}] IP: {COLOR_HIGHLIGHT}{ip} "
              f"| Port: {COLOR_INFO}{port} "
              f"| Org: {COLOR_SUCCESS}{org} "
              f"| Vulns: {COLOR_WARN}{vuln_text}")

    print("\n" + COLOR_TITLE + "="*60 + "\n")
    print(COLOR_SUCCESS + f"[✓] Shodan scan completed ({len(shodan_data)} results)\n")

# ----------------------------
# Pipeline-compatible function
# ----------------------------
def process(domain):
    """
    Shodan module for pipeline.py
    Returns JSON-ready dict (pipeline will save report)
    """
    try:
        print(COLOR_INFO + f"[*] Searching Shodan for {COLOR_HIGHLIGHT}{domain}...\n")
        results = api.search(domain)
        shodan_data = []

        for result in results.get("matches", []):
            ip = result.get("ip_str", "N/A")
            entry = {
                "ip": ip,
                "port": result.get("port", "N/A"),
                "org": result.get("org", "N/A"),
                "hostnames": result.get("hostnames", []),
                "location": result.get("location", {}),
                "vulnerabilities": list(result.get("vulns", {}).keys()) if "vulns" in result else []
            }
            shodan_data.append(entry)

        # Pretty CLI output
        pretty_print_shodan(domain, shodan_data)

        return {"shodan_results": shodan_data}

    except shodan.APIError as e:
        print(COLOR_ERROR + f"[!] Shodan API Error: {e}")
        return {"shodan_results": []}

# ----------------------------
# Standalone Test
# ----------------------------
if __name__ == "__main__":
    test_domain = "example.com"
    res = process(test_domain)
    print(COLOR_INFO + "JSON Output:")
    print(res)
