#!/usr/bin/env python3
import sys
import dns.resolver
from colorama import Fore, Style, init

# init colorama
init(autoreset=True)

# ---------------- SPF ----------------
def check_spf(domain):
    print(Fore.CYAN + f"[*] Checking SPF for {domain} ...")
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            record = str(rdata).strip('"')
            if record.startswith("v=spf1"):
                if "all" in record and "-all" not in record:
                    print(Fore.LIGHTRED_EX + f"[!] SPF record too permissive → {record}")
                    return [{"status": "vulnerable", "detail": f"SPF record too permissive: {record}"}]
                print(Fore.LIGHTGREEN_EX + f"[+] SPF properly configured → {record}")
                return [{"status": "secure", "detail": f"SPF properly configured: {record}"}]
        print(Fore.LIGHTRED_EX + "[!] No valid SPF record found")
        return [{"status": "vulnerable", "detail": "No valid SPF record found"}]
    except Exception as e:
        print(Fore.YELLOW + f"[!] SPF check failed → {e}")
        return [{"status": "error", "detail": f"SPF check failed: {e}"}]

# ---------------- DMARC ----------------
def check_dmarc(domain):
    print(Fore.CYAN + f"[*] Checking DMARC for {domain} ...")
    try:
        dmarc_domain = "_dmarc." + domain
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            record = str(rdata).strip('"')
            if record.startswith("v=DMARC1"):
                results = [{
                    "status": "found",
                    "full_record": record,
                    "main_policy": None,
                    "sub_policy": None
                }]

                if "p=reject" in record or "p=quarantine" in record:
                    results[0]["main_policy"] = "secure"
                    print(Fore.LIGHTGREEN_EX + f"[+] DMARC main policy is strict → {record}")
                elif "p=none" in record:
                    results[0]["main_policy"] = "vulnerable"
                    print(Fore.LIGHTRED_EX + f"[!] DMARC main policy is none → Vulnerable")
                else:
                    results[0]["main_policy"] = "unclear"
                    print(Fore.YELLOW + f"[?] DMARC main policy not clear → {record}")

                if "sp=reject" in record or "sp=quarantine" in record:
                    results[0]["sub_policy"] = "secure"
                    print(Fore.LIGHTGREEN_EX + "[+] DMARC subdomain policy is strict → Secure")
                elif "sp=none" in record:
                    results[0]["sub_policy"] = "vulnerable"
                    print(Fore.LIGHTRED_EX + "[!] DMARC subdomain policy is none → Vulnerable")
                else:
                    results[0]["sub_policy"] = "not_set"
                    print(Fore.YELLOW + "[?] No explicit DMARC subdomain policy set")

                return results

        print(Fore.LIGHTRED_EX + "[!] No valid DMARC record found")
        return [{"status": "vulnerable", "detail": "No valid DMARC record found"}]
    except Exception as e:
        print(Fore.YELLOW + f"[!] DMARC check failed → {e}")
        return [{"status": "error", "detail": f"DMARC check failed: {e}"}]

# ---------------- DKIM ----------------
def check_dkim(domain):
    print(Fore.CYAN + f"[*] Checking DKIM for {domain} ...")
    selectors = ["default", "selector1", "selector2", "google", "mail"]
    for selector in selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                record = str(rdata).strip('"')
                if record.startswith("v=DKIM1"):
                    print(Fore.LIGHTGREEN_EX + f"[+] DKIM found with selector '{selector}' → {record}")
                    return [{"status": "secure", "selector": selector, "record": record}]
        except:
            continue
    print(Fore.LIGHTRED_EX + "[!] No DKIM record found or misconfigured")
    return [{"status": "vulnerable", "detail": "No DKIM record found or misconfigured"}]

# ---------------- Pipeline Hook ----------------
def process(domain):
    """Entry point for pipeline.py"""
    return {
        "emailsecurity": {
            "spf": check_spf(domain),
            "dmarc": check_dmarc(domain),
            "dkim": check_dkim(domain)
        }
    }

# ---------------- CLI Mode ----------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(Fore.YELLOW + f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip()
    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + "\n===== Email Security Checks =====")
    results = process(domain)
    print(results)
    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + "=================================\n")
