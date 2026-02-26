#!/usr/bin/env python3
"""
dns_deep.py - Deep DNS Enumeration
Records: A, AAAA, MX, NS, TXT, SOA, CNAME, CAA
Also attempts: Zone Transfer (AXFR), DNSSEC check
"""
import json
import sys
from datetime import datetime
from colorama import Fore, Style, init

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

init(autoreset=True)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "SRV"]

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'─'*12}[ {title} ]{'─'*12}{Style.RESET_ALL}")

def ok(msg):   print(f"{Fore.GREEN}[✔]{Style.RESET_ALL} {msg}")
def warn(msg): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):  print(f"{Fore.RED}[✘]{Style.RESET_ALL} {msg}")
def info(msg): print(f"{Fore.BLUE}[➜]{Style.RESET_ALL} {msg}")


def query_records(domain, rtype):
    """Query a specific DNS record type."""
    records = []
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=10)
        for rdata in answers:
            records.append(str(rdata))
        ok(f"{rtype}: {len(records)} records")
        for r in records:
            print(f"   {Fore.LIGHTWHITE_EX}→ {r}")
    except dns.resolver.NXDOMAIN:
        warn(f"{rtype}: Domain does not exist")
    except dns.resolver.NoAnswer:
        pass  # No records of this type — normal
    except dns.resolver.Timeout:
        warn(f"{rtype}: Query timed out")
    except Exception as e:
        warn(f"{rtype}: {e}")
    return records


def attempt_zone_transfer(domain, nameservers):
    """Attempt DNS zone transfer (AXFR) against all nameservers."""
    result = {"attempted": True, "vulnerable": False, "records": []}
    banner("Zone Transfer (AXFR) Attempt")

    for ns in nameservers:
        ns_host = ns.rstrip(".")
        info(f"Trying AXFR on {ns_host}...")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=10))
            result["vulnerable"] = True
            for name, node in z.nodes.items():
                record = str(name)
                result["records"].append(record)
                print(f"   {Fore.RED}[ZONE LEAK] {record}")
            err(f"Zone transfer SUCCEEDED on {ns_host} — CRITICAL VULNERABILITY!")
            break
        except dns.exception.FormError:
            ok(f"AXFR refused by {ns_host} (secure)")
        except Exception:
            ok(f"AXFR refused/failed on {ns_host} (secure)")

    if not result["vulnerable"]:
        ok("Zone transfer not possible — all nameservers are secure")

    return result


def check_dnssec(domain):
    """Check if DNSSEC is enabled."""
    result = {"enabled": False, "detail": None}
    try:
        answers = dns.resolver.resolve(domain, "DNSKEY", lifetime=10)
        result["enabled"] = True
        result["detail"] = f"{len(list(answers))} DNSKEY record(s) found"
        ok(f"DNSSEC: Enabled — {result['detail']}")
    except dns.resolver.NoAnswer:
        warn("DNSSEC: Not configured (no DNSKEY records)")
        result["detail"] = "No DNSKEY records"
    except Exception as e:
        warn(f"DNSSEC: Could not verify — {e}")
        result["detail"] = str(e)
    return result


def check_wildcard(domain):
    """Check for wildcard DNS records."""
    import random, string
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=12)) + f".{domain}"
    try:
        dns.resolver.resolve(random_sub, "A", lifetime=5)
        warn(f"Wildcard DNS detected! Random subdomain {random_sub} resolved")
        return {"wildcard": True, "test_subdomain": random_sub}
    except Exception:
        ok("No wildcard DNS detected")
        return {"wildcard": False}


def process(domain):
    banner("Deep DNS Enumeration")

    if not HAS_DNS:
        err("dnspython not installed. Run: pip install dnspython")
        return {"error": "dnspython not installed"}

    info(f"Target: {domain}")
    info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    output = {
        "domain": domain,
        "records": {},
        "zone_transfer": None,
        "dnssec": None,
        "wildcard": None,
        "scanned_at": datetime.now().isoformat()
    }

    # Query all record types
    banner("DNS Record Enumeration")
    nameservers = []
    for rtype in RECORD_TYPES:
        records = query_records(domain, rtype)
        if records:
            output["records"][rtype] = records
            if rtype == "NS":
                nameservers = records

    # Zone Transfer
    if nameservers:
        output["zone_transfer"] = attempt_zone_transfer(domain, nameservers)
    else:
        warn("No NS records found — skipping zone transfer")

    # DNSSEC
    banner("DNSSEC Check")
    output["dnssec"] = check_dnssec(domain)

    # Wildcard
    banner("Wildcard DNS Check")
    output["wildcard"] = check_wildcard(domain)

    # Summary
    banner("DNS Summary")
    print(f"  {Fore.WHITE}Record types found: {Fore.CYAN}{list(output['records'].keys())}")
    print(f"  {Fore.WHITE}Zone transfer vuln: {Fore.RED if output['zone_transfer'] and output['zone_transfer']['vulnerable'] else Fore.GREEN}{output['zone_transfer']['vulnerable'] if output['zone_transfer'] else 'N/A'}")
    print(f"  {Fore.WHITE}DNSSEC enabled:     {Fore.GREEN if output['dnssec']['enabled'] else Fore.YELLOW}{output['dnssec']['enabled']}")
    print(f"  {Fore.WHITE}Wildcard DNS:       {Fore.RED if output['wildcard']['wildcard'] else Fore.GREEN}{output['wildcard']['wildcard']}")

    return output


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    result = process(domain)
    print(json.dumps(result, indent=2, default=str))
