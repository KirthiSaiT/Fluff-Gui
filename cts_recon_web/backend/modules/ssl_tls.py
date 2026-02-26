#!/usr/bin/env python3
"""
ssl_tls.py - SSL/TLS Certificate & Configuration Analysis
Checks: cert expiry, TLS version, issuer, SANs, HSTS, weak ciphers
"""
import ssl
import socket
import requests
import json
from datetime import datetime, timezone
from colorama import Fore, Style, init

init(autoreset=True)

TIMEOUT = 10

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'-'*12}[ {title} ]{'-'*12}{Style.RESET_ALL}")

def ok(msg):   print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):  print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def info(msg): print(f"{Fore.BLUE}[>]{Style.RESET_ALL} {msg}")


def get_certificate_info(domain):
    """Fetch raw SSL certificate from domain:443."""
    result = {
        "domain": domain,
        "port": 443,
        "reachable": False,
        "subject": {},
        "issuer": {},
        "san": [],
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "expired": False,
        "expiring_soon": False,
        "tls_version": None,
        "cipher": None,
        "error": None
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result["reachable"] = True
                result["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                result["cipher"] = {
                    "name": cipher[0],
                    "protocol": cipher[1],
                    "bits": cipher[2]
                }

                cert = ssock.getpeercert()

                # Subject
                subject = dict(x[0] for x in cert.get("subject", []))
                result["subject"] = subject
                ok(f"Subject CN: {subject.get('commonName', 'N/A')}")

                # Issuer
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer
                ok(f"Issuer: {issuer.get('organizationName', 'N/A')}")

                # SANs
                sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                result["san"] = sans
                ok(f"SANs: {len(sans)} entries")

                # Validity
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)

                result["valid_from"]  = not_before.isoformat()
                result["valid_until"] = not_after.isoformat()

                days = (not_after - now).days
                result["days_remaining"] = days
                result["expired"] = days < 0
                result["expiring_soon"] = 0 <= days <= 30

                if days < 0:
                    err(f"Certificate EXPIRED {abs(days)} days ago!")
                elif days <= 30:
                    warn(f"Certificate expiring in {days} days!")
                else:
                    ok(f"Certificate valid for {days} more days")

                # TLS Version check
                tls = ssock.version()
                result["tls_version"] = tls
                if tls in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    warn(f"Weak TLS version in use: {tls}")
                else:
                    ok(f"TLS Version: {tls}")

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e}"
        err(result["error"])
    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {e}"
        err(result["error"])
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Connection failed: {e}"
        err(result["error"])

    return result


def check_hsts(domain):
    """Check if HSTS is present and configured properly."""
    result = {"enabled": False, "max_age": None, "include_subdomains": False, "preload": False, "raw": None}
    try:
        r = requests.get(f"https://{domain}", timeout=TIMEOUT, verify=False, allow_redirects=True)
        hsts = r.headers.get("Strict-Transport-Security", "")
        if hsts:
            result["enabled"] = True
            result["raw"] = hsts
            for part in hsts.lower().split(";"):
                part = part.strip()
                if part.startswith("max-age"):
                    try:
                        result["max_age"] = int(part.split("=")[1])
                    except Exception:
                        pass
                elif part == "includesubdomains":
                    result["include_subdomains"] = True
                elif part == "preload":
                    result["preload"] = True
            ok(f"HSTS enabled: max-age={result['max_age']}, includeSubDomains={result['include_subdomains']}")
        else:
            warn("HSTS header missing — vulnerable to downgrade attacks")
    except Exception as e:
        result["error"] = str(e)
    return result


def check_http_redirect(domain):
    """Check if HTTP redirects to HTTPS."""
    result = {"redirects_to_https": False, "redirect_chain": []}
    try:
        r = requests.get(f"http://{domain}", timeout=TIMEOUT, allow_redirects=True)
        result["redirect_chain"] = [str(resp.url) for resp in r.history] + [str(r.url)]
        if r.url.startswith("https://"):
            result["redirects_to_https"] = True
            ok("HTTP → HTTPS redirect configured correctly")
        else:
            warn("HTTP does NOT redirect to HTTPS")
    except Exception as e:
        result["error"] = str(e)
    return result


def process(domain):
    banner("SSL / TLS Analysis")
    info(f"Target: {domain}")

    cert = get_certificate_info(domain)

    banner("HSTS Check")
    hsts = check_hsts(domain)

    banner("HTTP→HTTPS Redirect")
    redirect = check_http_redirect(domain)

    output = {
        "certificate": cert,
        "hsts": hsts,
        "http_redirect": redirect,
        "summary": {
            "expired": cert.get("expired"),
            "expiring_soon": cert.get("expiring_soon"),
            "days_remaining": cert.get("days_remaining"),
            "tls_version": cert.get("tls_version"),
            "hsts_enabled": hsts.get("enabled"),
            "https_redirect": redirect.get("redirects_to_https"),
        }
    }

    banner("SSL/TLS Summary")
    for k, v in output["summary"].items():
        print(f"  {Fore.WHITE}{k}: {Fore.LIGHTCYAN_EX}{v}")

    return output


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    result = process(domain)
    print(json.dumps(result, indent=2, default=str))


