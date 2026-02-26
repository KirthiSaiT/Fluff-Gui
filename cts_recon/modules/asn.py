#!/usr/bin/env python3
"""
asn.py - ASN & IP Range Discovery
APIs used (with fallback chain):
  1. ipinfo.io       — primary   (no auth needed, reliable)
  2. ip-api.com      — secondary (free, no auth)
  3. bgpview.io      — tertiary  (detailed but sometimes unreachable)
"""
import requests
import socket
import json
import sys
from datetime import datetime
from colorama import Fore, Style, init
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

TIMEOUT = 12
BGPVIEW_BASE = "https://api.bgpview.io"
IPINFO_BASE  = "https://ipinfo.io"
IPAPI_BASE   = "http://ip-api.com/json"   # HTTP (no TLS issue)
RDAP_BASE    = "https://rdap.arin.net/registry/ip"

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'-'*12}[ {title} ]{'-'*12}{Style.RESET_ALL}")

def ok(msg):      print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):     print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def info(msg):    print(f"{Fore.BLUE}[>]{Style.RESET_ALL} {msg}")
def finding(msg): print(f"{Fore.LIGHTWHITE_EX}> {msg}{Style.RESET_ALL}")


def resolve_domain(domain):
    """Resolve domain to all IPs."""
    ips = []
    try:
        results = socket.getaddrinfo(domain, None)
        seen = set()
        for r in results:
            ip = r[4][0]
            if ip not in seen and not ip.startswith("127.") and not ip.startswith("::"):
                seen.add(ip)
                ips.append(ip)
        ok(f"Resolved {domain} → {ips}")
    except Exception as e:
        err(f"DNS resolution failed: {e}")
    return ips


# -- API 1: ipinfo.io (primary, most reliable) --------------------------------

def lookup_ipinfo(ip):
    """Primary: ipinfo.io — always up, no auth required for basic data."""
    try:
        r = requests.get(f"{IPINFO_BASE}/{ip}/json", timeout=TIMEOUT,
                         headers={"Accept": "application/json"})
        if r.status_code == 200:
            d = r.json()
            org = d.get("org", "")          # e.g. "AS15169 Google LLC"
            asn, asn_name = None, None
            if org and org.startswith("AS"):
                parts = org.split(" ", 1)
                try:
                    asn = int(parts[0][2:])
                    asn_name = parts[1] if len(parts) > 1 else ""
                except Exception:
                    pass

            result = {
                "source": "ipinfo.io",
                "ip": ip,
                "asn": asn,
                "asn_name": asn_name,
                "org": org,
                "hostname": d.get("hostname"),
                "city": d.get("city"),
                "region": d.get("region"),
                "country": d.get("country"),
                "loc": d.get("loc"),
                "timezone": d.get("timezone"),
                "postal": d.get("postal"),
            }
            ok(f"[ipinfo.io] {ip} → {org} | {d.get('city')}, {d.get('country')}")
            if asn:
                finding(f"ASN: AS{asn} ({asn_name})")
            return result
    except Exception as e:
        warn(f"ipinfo.io failed: {e}")
    return None


# -- API 2: ip-api.com (secondary, uses HTTP so avoids TLS issues) -------------

def lookup_ipapi(ip):
    """Secondary: ip-api.com — HTTP endpoint, rarely blocked."""
    try:
        fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"
        r = requests.get(f"{IPAPI_BASE}/{ip}?fields={fields}", timeout=TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                asn_raw = d.get("as", "")     # e.g. "AS15169 Google LLC"
                asn, asn_name = None, None
                if asn_raw.startswith("AS"):
                    parts = asn_raw.split(" ", 1)
                    try:
                        asn = int(parts[0][2:])
                        asn_name = parts[1] if len(parts) > 1 else d.get("asname", "")
                    except Exception:
                        pass

                result = {
                    "source": "ip-api.com",
                    "ip": ip,
                    "asn": asn,
                    "asn_name": asn_name or d.get("asname"),
                    "org": d.get("org"),
                    "isp": d.get("isp"),
                    "city": d.get("city"),
                    "region": d.get("regionName"),
                    "country": d.get("country"),
                    "country_code": d.get("countryCode"),
                    "lat": d.get("lat"),
                    "lon": d.get("lon"),
                    "timezone": d.get("timezone"),
                }
                ok(f"[ip-api.com] {ip} → AS{asn} {asn_name} | ISP: {d.get('isp')}")
                return result
    except Exception as e:
        warn(f"ip-api.com failed: {e}")
    return None


# -- API 3: bgpview.io (tertiary, richest data but can be down) ---------------

def lookup_bgpview(ip):
    """Tertiary: bgpview.io — richest prefix/ASN data but sometimes unreachable."""
    try:
        r = requests.get(f"{BGPVIEW_BASE}/ip/{ip}", timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json().get("data", {})
            prefixes = data.get("prefixes", [])
            result = {
                "source": "bgpview.io",
                "ip": ip,
                "rir_allocation": data.get("rir_allocation", {}),
                "prefixes": []
            }
            for prefix in prefixes:
                asn_info = prefix.get("asn", {})
                p = {
                    "prefix": prefix.get("prefix"),
                    "asn": asn_info.get("asn"),
                    "asn_name": asn_info.get("name"),
                    "country_code": prefix.get("country_code"),
                    "name": prefix.get("name"),
                }
                result["prefixes"].append(p)
                finding(f"Prefix: {p['prefix']} | AS{p['asn']} ({p['asn_name']}) | {p['country_code']}")
            ok(f"[bgpview.io] {len(prefixes)} prefix(es) for {ip}")
            return result
    except Exception as e:
        warn(f"bgpview.io unreachable: {e}")
    return None


def get_ip_info_with_fallback(ip):
    """Try all 3 APIs in order, return first successful result."""
    info(f"Looking up {ip}...")

    # Try ipinfo.io first
    result = lookup_ipinfo(ip)
    if result:
        # Also try bgpview for richer prefix data (non-blocking)
        bv = lookup_bgpview(ip)
        if bv:
            result["bgpview_prefixes"] = bv.get("prefixes", [])
            result["rir_allocation"]   = bv.get("rir_allocation", {})
        return result

    # Fallback to ip-api.com
    result = lookup_ipapi(ip)
    if result:
        return result

    # Final fallback: RDAP (ARIN)
    try:
        r = requests.get(f"{RDAP_BASE}/{ip}", timeout=TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            result = {
                "source": "rdap.arin.net",
                "ip": ip,
                "name": d.get("name"),
                "type": d.get("type"),
                "handle": d.get("handle"),
            }
            ok(f"[RDAP] {ip} → {d.get('name')}")
            return result
    except Exception as e:
        warn(f"RDAP also failed: {e}")

    err(f"All ASN APIs failed for {ip} — check your internet connection")
    return {"ip": ip, "source": "none", "error": "All APIs unreachable"}


def get_asn_prefixes_with_fallback(asn_number):
    """Get full ASN prefix list. Tries bgpview first, then HackerTarget as fallback."""
    result = {"asn": asn_number, "prefixes_v4": [], "prefixes_v6": []}
    
    # 1. Try BGPView
    try:
        r = requests.get(f"{BGPVIEW_BASE}/asn/{asn_number}/prefixes", timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json().get("data", {})
            for p in data.get("ipv4_prefixes", []):
                result["prefixes_v4"].append({
                    "prefix": p.get("prefix"),
                    "name": p.get("name"),
                    "country_code": p.get("country_code")
                })
                finding(f"[bgpview] IPv4 Block: {p.get('prefix')} ({p.get('name', 'N/A')})")
            for p in data.get("ipv6_prefixes", []):
                result["prefixes_v6"].append({"prefix": p.get("prefix"), "name": p.get("name")})
            
            ok(f"IPv4: {len(result['prefixes_v4'])} | IPv6: {len(result['prefixes_v6'])} blocks found")
            return result
    except Exception as e:
        warn(f"bgpview prefix fetch failed: {e}")

    # 2. Try HackerTarget Fallback
    info("Trying HackerTarget fallback for ASN prefixes...")
    try:
        r = requests.get(f"https://api.hackertarget.com/aslookup/?q=AS{asn_number}", timeout=TIMEOUT)
        if r.status_code == 200 and r.text:
            lines = r.text.split("\n")
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # HackerTarget returns: 208.115.224.0/20
                if "/" in line and ":" not in line: # Basic IPv4 distinction
                    result["prefixes_v4"].append({
                        "prefix": line,
                        "name": f"HackerTarget Recon",
                        "country_code": "Unknown"
                    })
                    finding(f"[hackertarget] IPv4 Block: {line}")
            
            ok(f"HackerTarget found {len(result['prefixes_v4'])} blocks")
            return result
    except Exception as e:
        warn(f"HackerTarget ASN prefix fetch failed: {e}")

    err(f"Could not fetch prefixes for AS{asn_number}")
    return result



def process(domain):
    banner("ASN & IP Range Discovery")
    info(f"Target: {domain}")
    info(f"APIs: ipinfo.io → ip-api.com → bgpview.io (fallback chain)")

    output = {
        "domain": domain,
        "resolved_ips": [],
        "ip_details": [],
        "asn_summary": [],
        "all_ipv4_blocks": [],
        "scanned_at": datetime.now().isoformat()
    }

    # 1. Resolve IPs
    banner("DNS Resolution")
    ips = resolve_domain(domain)
    output["resolved_ips"] = ips

    if not ips:
        err("No IPs resolved — cannot continue ASN lookup")
        return output

    # 2. Look up each IP
    seen_asns = set()
    banner("IP → ASN Lookup")
    for ip in ips:
        data = get_ip_info_with_fallback(ip)
        output["ip_details"].append(data)
        asn = data.get("asn")
        if asn:
            seen_asns.add(asn)

    # 3. For each ASN, get full prefix list
    banner("IP Block Discovery")
    for asn in seen_asns:
        info(f"Fetching prefix list for AS{asn}...")
        asn_data = get_asn_prefixes_with_fallback(asn)
        output["asn_summary"].append(asn_data)
        for block in asn_data.get("prefixes_v4", []):
            block["owned_by_asn"] = asn
            output["all_ipv4_blocks"].append(block)

    # Summary
    banner("ASN Summary")
    print(f"  {Fore.WHITE}Resolved IPs:   {Fore.CYAN}{output['resolved_ips']}")
    print(f"  {Fore.WHITE}ASNs found:     {Fore.CYAN}{list(seen_asns)}")
    print(f"  {Fore.WHITE}IPv4 blocks:    {Fore.CYAN}{len(output['all_ipv4_blocks'])}")
    for block in output["all_ipv4_blocks"][:10]:
        print(f"   {Fore.LIGHTWHITE_EX}→ {block['prefix']} ({block.get('name', 'N/A')})")
    if len(output["all_ipv4_blocks"]) > 10:
        print(f"   {Fore.YELLOW}... and {len(output['all_ipv4_blocks']) - 10} more")

    return output


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    result = process(domain)
    print(json.dumps(result, indent=2, default=str))


