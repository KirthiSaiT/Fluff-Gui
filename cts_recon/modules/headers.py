#!/usr/bin/env python3
"""
headers.py - HTTP Security Headers Audit
Checks: CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
        X-XSS-Protection, Referrer-Policy, Permissions-Policy, CORS
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

# Security headers to audit with their expected values / descriptions
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HSTS — forces HTTPS",
        "recommend": "max-age=31536000; includeSubDomains; preload",
        "required": True
    },
    "Content-Security-Policy": {
        "desc": "CSP — prevents XSS, injection",
        "recommend": "default-src 'self'",
        "required": True
    },
    "X-Frame-Options": {
        "desc": "Clickjacking protection",
        "recommend": "DENY or SAMEORIGIN",
        "required": True
    },
    "X-Content-Type-Options": {
        "desc": "MIME sniffing protection",
        "recommend": "nosniff",
        "required": True
    },
    "Referrer-Policy": {
        "desc": "Controls referrer info sent",
        "recommend": "no-referrer or strict-origin-when-cross-origin",
        "required": True
    },
    "Permissions-Policy": {
        "desc": "Controls browser features (camera, mic, etc.)",
        "recommend": "geolocation=(), microphone=(), camera=()",
        "required": False
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS protection (older browsers)",
        "recommend": "1; mode=block",
        "required": False
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Isolates browsing context",
        "recommend": "same-origin",
        "required": False
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "Prevents cross-origin resource inclusion",
        "recommend": "same-origin",
        "required": False
    },
    "Cross-Origin-Embedder-Policy": {
        "desc": "Requires CORP for resources",
        "recommend": "require-corp",
        "required": False
    }
}

# Dangerous CSP directives
WEAK_CSP_PATTERNS = [
    "unsafe-inline",
    "unsafe-eval",
    "data:",
    "*",
    "http:",
]

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'-'*12}[ {title} ]{'-'*12}{Style.RESET_ALL}")

def ok(msg):   print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):  print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def info(msg): print(f"{Fore.BLUE}[>]{Style.RESET_ALL} {msg}")


def fetch_headers(url):
    """Fetch HTTP response headers from a URL."""
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (Security Scanner)"})
        return r.headers, r.status_code, str(r.url)
    except Exception as e:
        return None, None, str(e)


def audit_csp(csp_value):
    """Audit a CSP value for weak directives."""
    issues = []
    for pattern in WEAK_CSP_PATTERNS:
        if pattern in csp_value:
            issues.append(f"Dangerous directive: '{pattern}'")
    return issues


def analyze_headers(headers):
    """Analyze response headers against security checklist."""
    results = {}
    missing_critical = []
    present = 0
    total = len(SECURITY_HEADERS)

    for header, meta in SECURITY_HEADERS.items():
        value = headers.get(header, None) if headers else None
        entry = {
            "present": value is not None,
            "value": value,
            "description": meta["desc"],
            "recommendation": meta["recommend"],
            "required": meta["required"],
            "issues": []
        }

        if value:
            present += 1
            # CSP-specific audit
            if header == "Content-Security-Policy":
                entry["issues"] = audit_csp(value)
                if entry["issues"]:
                    warn(f"CSP present but weak: {entry['issues']}")
                else:
                    ok(f"{header}: ✓")
            else:
                ok(f"{header}: {value[:60]}{'...' if len(value) > 60 else ''}")
        else:
            if meta["required"]:
                missing_critical.append(header)
                err(f"MISSING (critical): {header} — {meta['desc']}")
            else:
                warn(f"Missing (optional): {header} — {meta['desc']}")

        results[header] = entry

    score = round((present / total) * 100)
    return results, missing_critical, score


def process(domain):
    banner("HTTP Security Headers Audit")
    info(f"Target: {domain}")

    output = {
        "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "endpoints": {},
        "summary": {}
    }

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        info(f"Fetching {url}...")
        headers, status_code, final_url = fetch_headers(url)

        if headers is None:
            warn(f"Could not reach {url}")
            continue

        ok(f"Response: HTTP {status_code} → {final_url}")
        banner(f"Header Analysis ({scheme.upper()})")
        results, missing_critical, score = analyze_headers(headers)

        output["endpoints"][scheme] = {
            "url": final_url,
            "status_code": status_code,
            "headers_found": results,
            "missing_critical": missing_critical,
            "security_score": score,
            "raw_headers": dict(headers)
        }

        # Only do HTTPS (if it works)
        if scheme == "https":
            break

    # Summary
    best = output["endpoints"].get("https") or output["endpoints"].get("http", {})
    output["summary"] = {
        "security_score": best.get("security_score", 0),
        "missing_critical_headers": best.get("missing_critical", []),
        "total_checked": len(SECURITY_HEADERS)
    }

    banner("Security Score")
    score = output["summary"]["security_score"]
    color = Fore.GREEN if score >= 80 else Fore.YELLOW if score >= 50 else Fore.RED
    print(f"  {color}{Style.BRIGHT}Score: {score}/100")
    if output["summary"]["missing_critical_headers"]:
        err(f"Fix these: {output['summary']['missing_critical_headers']}")

    return output


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    result = process(domain)
    print(json.dumps(result, indent=2, default=str))


