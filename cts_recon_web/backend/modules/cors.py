#!/usr/bin/env python3
"""
cors.py - CORS Misconfiguration Tester
Tests: wildcard origin, arbitrary origin reflection, null origin,
       subdomain prefix/suffix bypass, credential leakage
"""
import requests
import json
import sys
from datetime import datetime
from colorama import Fore, Style, init
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

TIMEOUT = 10

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'─'*12}[ {title} ]{'─'*12}{Style.RESET_ALL}")

def ok(msg):     print(f"{Fore.GREEN}[✔]{Style.RESET_ALL} {msg}")
def warn(msg):   print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):    print(f"{Fore.RED}[✘ VULNERABLE]{Style.RESET_ALL} {msg}")
def info(msg):   print(f"{Fore.BLUE}[➜]{Style.RESET_ALL} {msg}")
def finding(msg):print(f"{Fore.MAGENTA}[★]{Style.RESET_ALL} {msg}")


def build_test_origins(domain):
    """Generate a set of test origins to probe CORS policy."""
    return [
        # Exact origin reflection
        (f"https://{domain}", "Exact origin"),
        # Null origin (iframe sandbox bypass)
        ("null", "Null origin"),
        # Wildcard check (will show in response)
        ("https://evil.com", "Arbitrary origin"),
        # Prefix bypass: evil.com prefixed with target
        (f"https://{domain}.evil.com", "Prefix bypass"),
        # Suffix bypass: evil.com suffixed to target
        (f"https://evil{domain}", "Suffix bypass"),
        # HTTP downgrade
        (f"http://{domain}", "HTTP downgrade"),
        # Subdomain trust
        (f"https://malicious.{domain}", "Subdomain trust"),
        # XSS + CORS combo check
        (f"https://notreally{domain}.com", "Not-really prefix"),
    ]


def test_cors_origin(url, origin, label):
    """Test a single Origin against the target URL."""
    result = {
        "origin_sent": origin,
        "label": label,
        "acao": None,
        "acac": None,
        "vulnerable": False,
        "reason": None
    }

    try:
        headers = {
            "Origin": origin,
            "User-Agent": "Mozilla/5.0 (CORS Security Scanner)"
        }
        r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")

        result["acao"] = acao
        result["acac"] = acac

        # Vulnerability checks
        if acao == "*":
            if acac.lower() == "true":
                result["vulnerable"] = True
                result["reason"] = "Wildcard origin with credentials — CRITICAL"
                err(f"[{label}] CRITICAL: * + credentials=true is invalid but some parsers allow it!")
            else:
                warn(f"[{label}] Wildcard (*): Public data exposed, no credential risk")

        elif acao == origin and origin not in (f"https://{url.split('/')[2]}", ""):
            if acac.lower() == "true":
                result["vulnerable"] = True
                result["reason"] = f"Origin '{origin}' reflected with credentials=true — HIGH RISK"
                err(f"[{label}] Origin reflected with credentials: {origin}")
            else:
                warn(f"[{label}] Origin reflected (no credentials): {origin}")
                result["reason"] = "Origin reflected without credentials (low risk)"

        elif acao == "null" and origin == "null":
            result["vulnerable"] = True
            result["reason"] = "Null origin accepted — can be exploited via sandboxed iframes"
            err(f"[{label}] Null origin accepted!")

        else:
            ok(f"[{label}] Not reflected — secure")

    except Exception as e:
        result["error"] = str(e)
        warn(f"[{label}] Request failed: {e}")

    return result


def test_preflight(url, origin):
    """Test OPTIONS preflight CORS response."""
    result = {"preflight_tested": False, "allowed_methods": None, "allowed_headers": None}
    try:
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization, Content-Type"
        }
        r = requests.options(url, headers=headers, timeout=TIMEOUT, verify=False)
        result["preflight_tested"] = True
        result["allowed_methods"] = r.headers.get("Access-Control-Allow-Methods")
        result["allowed_headers"] = r.headers.get("Access-Control-Allow-Headers")
        result["status_code"] = r.status_code

        if result["allowed_headers"] and "authorization" in result["allowed_headers"].lower():
            warn(f"Preflight allows Authorization header from {origin}")
    except Exception as e:
        result["error"] = str(e)
    return result


def process(domain):
    banner("CORS Misconfiguration Test")
    info(f"Target: {domain}")

    url = f"https://{domain}"
    test_origins = build_test_origins(domain)

    results = []
    vulnerabilities = []
    warnings = []

    banner("Origin Reflection Tests")
    for origin, label in test_origins:
        r = test_cors_origin(url, origin, label)
        results.append(r)
        if r.get("vulnerable"):
            vulnerabilities.append(r)
        elif r.get("acao") and r.get("acao") != "":
            warnings.append(r)

    banner("Preflight (OPTIONS) Test")
    preflight = test_preflight(url, f"https://evil.com")

    # Also test common API endpoints
    api_results = []
    for path in ["/api", "/api/v1", "/graphql", "/rest"]:
        api_url = f"https://{domain}{path}"
        r = test_cors_origin(api_url, "https://evil.com", f"API path {path}")
        if r.get("vulnerable"):
            api_results.append(r)

    output = {
        "domain": domain,
        "url_tested": url,
        "tests": results,
        "preflight": preflight,
        "api_endpoint_tests": api_results,
        "vulnerabilities": vulnerabilities,
        "warnings": warnings,
        "scanned_at": datetime.now().isoformat(),
        "summary": {
            "total_tests": len(results),
            "vulnerable": len(vulnerabilities),
            "warnings": len(warnings),
            "risk_level": "HIGH" if vulnerabilities else "MEDIUM" if warnings else "LOW"
        }
    }

    banner("CORS Summary")
    risk = output["summary"]["risk_level"]
    color = Fore.RED if risk == "HIGH" else Fore.YELLOW if risk == "MEDIUM" else Fore.GREEN
    print(f"  {color}{Style.BRIGHT}Risk Level: {risk}")
    print(f"  {Fore.WHITE}Vulnerabilities found: {Fore.RED}{len(vulnerabilities)}")
    print(f"  {Fore.WHITE}Warnings: {Fore.YELLOW}{len(warnings)}")
    if vulnerabilities:
        for v in vulnerabilities:
            finding(f"{v['label']}: {v['reason']}")

    return output


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    result = process(domain)
    print(json.dumps(result, indent=2, default=str))
