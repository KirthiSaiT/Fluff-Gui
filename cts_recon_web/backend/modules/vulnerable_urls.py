#!/usr/bin/env python3
import os
import json
import subprocess
from colorama import init, Fore, Style

# ==============================
# CONFIG
# ==============================
GF_PATTERNS = [
    "xss", "ssrf", "sqli", "rce", "redirect", "lfi", "ssti",
    "idor", "rfi"
]

# ==============================
# Run gau + gf
# ==============================
def run_gau(domain):
    """Run gau to fetch URLs for a domain"""
    print(Fore.LIGHTBLUE_EX + f"\n[*] Running gau for {domain} ...")
    try:
        result = subprocess.run(
            ["gau", "--subs", domain],
            capture_output=True,
            text=True,
            check=True,
            timeout=120  # Timeout after 2 minutes
        )
        urls = list(set(result.stdout.splitlines()))
        print(Fore.LIGHTGREEN_EX + f"[+] Found {len(urls)} URLs from gau")
        return urls
    except subprocess.TimeoutExpired:
        print(Fore.LIGHTYELLOW_EX + f"[!] gau timed out (limit reached). Proceeding with partial/empty results.")
        return []
    except subprocess.CalledProcessError as e:
        print(Fore.LIGHTYELLOW_EX + f"[!] gau failed: {e}")
        return []


def run_gf(urls, pattern):
    """Run gf pattern filter on a list of URLs"""
    try:
        proc = subprocess.Popen(
            ["gf", pattern],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, _ = proc.communicate("\n".join(urls))
        return stdout.splitlines() if stdout else []
    except Exception as e:
        print(Fore.LIGHTYELLOW_EX + f"[!] gf {pattern} failed: {e}")
        return []


def process(domain):
    """Pipeline hook for gau + gf"""
    all_results = {}
    urls = run_gau(domain)

    if not urls:
        return {"gau_urls": [], "gf_results": {}}

    # Save raw gau output
    all_results["gau_urls"] = urls

    # Run gf filters
    gf_results = {}
    for pattern in GF_PATTERNS:
        print(Fore.LIGHTCYAN_EX + f"[+] Running gf {pattern} ...")
        filtered = run_gf(urls, pattern)
        gf_results[pattern] = filtered
        print(Fore.LIGHTYELLOW_EX + f"    Found {len(filtered)} {pattern} URLs")

    all_results["gf_results"] = gf_results
    return all_results


# ==============================
# CLI Mode
# ==============================
if __name__ == "__main__":
    init()
    domain = input(Fore.LIGHTBLUE_EX + "\nEnter the target domain (e.g., example.com): ").strip()
    if not domain:
        print(Fore.LIGHTYELLOW_EX + "Target domain required. Exiting.")
        exit()

    print(Style.BRIGHT + Fore.LIGHTBLUE_EX + f"\nProcessing domain: {domain}")
    results = process(domain)

    file_path = f"{domain}_vuln_urls.json"
    with open(file_path, "w") as f:
        json.dump(results, f, indent=4)

    print(Fore.LIGHTGREEN_EX + f"\nResults saved to {file_path}")
    print(Fore.LIGHTBLUE_EX + "\nProcess complete.\n")
