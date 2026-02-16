#!/usr/bin/env python3
import subprocess
import requests
import json
import os
import re
import tempfile
import sys
from datetime import datetime
from colorama import Fore, Style, init

# ============== CLI Styling ==============
init(autoreset=True)

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'─'*12}[ {title} ]{'─'*12}{Style.RESET_ALL}")

def info(msg):
    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {msg}")

def ok(msg):
    print(f"{Fore.GREEN}[✔]{Style.RESET_ALL} {msg}")

def warn(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def err(msg):
    print(f"{Fore.RED}[✘]{Style.RESET_ALL} {msg}")

def finding(msg):
    print(f"{Fore.LIGHTWHITE_EX}➜ {msg}{Style.RESET_ALL}")

def is_tool_missing(name):
    try:
        subprocess.run([name, "-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return False
    except FileNotFoundError:
        return True

# ============== Utilities ==============
def stream_command(cmd, on_line=None, quiet_stderr=True):
    """
    Run a command and stream stdout line-by-line to the handler.
    Suppresses stderr unless quiet_stderr=False.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=(subprocess.DEVNULL if quiet_stderr else subprocess.PIPE),
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        if proc.stdout is not None:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                if on_line:
                    on_line(line)
        proc.wait()
        return proc.returncode
    except FileNotFoundError:
        raise
    except Exception as e:
        err(f"Command failed: {' '.join(cmd)} -> {e}")
        return 1

# ============== Subdomain Sources ==============
def run_subfinder(domain):
    subs = set()
    if is_tool_missing("subfinder"):
        warn("subfinder not found; skipping (install: https://github.com/projectdiscovery/subfinder)")
        return subs

    info(f"Running subfinder for {domain}")
    def handle(line):
        # subfinder prints subdomains directly
        subs.add(line)
        finding(f"subfinder: {line}")

    try:
        rc = stream_command(
            ["subfinder", "-d", domain, "-silent"],
            on_line=handle
        )
        if rc == 0:
            ok(f"Subfinder done. Collected {len(subs)}")
        else:
            warn(f"Subfinder exited with code {rc}. Collected {len(subs)}")
    except FileNotFoundError:
        err("Error: subfinder binary not found.")
    return subs


def run_crtsh(domain):
    subs = set()
    info(f"Fetching crt.sh results for {domain}")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        # Retry mechanism for crt.sh
        for attempt in range(3):
            try:
                resp = requests.get(url, timeout=20)
                if resp.status_code == 200:
                    break
            except requests.RequestException:
                if attempt < 2:
                    warn(f"crt.sh request timed out. Retrying ({attempt+1}/3)...")
                    continue
                else:
                    raise
        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                # crt.sh sometimes returns multiple JSON objects concatenated; fallback with regex
                data = []
                for m in re.finditer(r"\{.*?\}", resp.text, re.DOTALL):
                    try:
                        data.append(json.loads(m.group(0)))
                    except Exception:
                        pass
            for entry in data:
                name = entry.get("name_value")
                if not name:
                    continue
                for sub in str(name).split("\n"):
                    sub = sub.strip()
                    if sub and "*" not in sub:
                        if sub.endswith("." + domain) or sub == domain or domain in sub:
                            if sub not in subs:
                                subs.add(sub)
                                finding(f"crt.sh: {sub}")
        else:
            warn(f"crt.sh returned HTTP {resp.status_code}")
    except requests.RequestException as e:
        err(f"crt.sh request failed: {e}")
    ok(f"crt.sh done. Collected {len(subs)}")
    return subs


def run_dnsbrute(domain, wordlist="modules/subdomains-top1million-5000.txt"):
    """
    Uses ffuf to brute-force subdomains: https://FUZZ.<domain>
    Parses streaming output and extracts confirmed hosts.
    """
    subs = set()
    banner("DNS Brute Force (ffuf)")

    if is_tool_missing("ffuf"):
        warn("ffuf not found; skipping (install: go install github.com/ffuf/ffuf@latest)")
        return subs

    if not os.path.exists(wordlist):
        warn(f"Wordlist not found: {wordlist} (skipping ffuf)")
        return subs

    info(f"Wordlist: {wordlist}")
    cmd = [
        "ffuf",
        "-s",
        "-u", f"https://FUZZ.{domain}",
        "-w", wordlist,
        "-mc", "200,301,302,403",  # include common statuses
        "-t", "200",
        "-rate", "400",
        "-timeout", "3",
        "-replay-proxy", ""  # make output cleaner if user had envs
    ]

    # Patterns: ffuf prints lines like:
    # "admin      [Status: 200, Size: 123, Words: 10, Lines: 2]"
    # We reconstruct subdomain as "<token>.<domain>"
    token_line = re.compile(r"^([A-Za-z0-9][A-Za-z0-9\-._]{0,63})\s+\[Status:\s*(\d+)", re.I)
    # Or sometimes it may print full URL
    url_line = re.compile(r"https?://([A-Za-z0-9\.-]+)", re.I)

    def handle(line):
        m1 = token_line.search(line)
        m2 = url_line.search(line)
        host = None
        if m2:
            host = m2.group(1)
        elif m1:
            token = m1.group(1).strip(".")
            # avoid dots at ends; if token already contains domain, use as-is
            if token.endswith(domain):
                host = token
            else:
                host = f"{token}.{domain}"

        if host and host not in subs:
            subs.add(host)
            finding(f"ffuf: {host}")

    try:
        rc = stream_command(cmd, on_line=handle)
        if rc == 0:
            ok(f"ffuf done. Collected {len(subs)}")
        else:
            warn(f"ffuf exited with code {rc}. Collected {len(subs)}")
    except FileNotFoundError:
        err("Error: ffuf binary not found.")
    except Exception as e:
        err(f"ffuf failed: {e}")
    return subs


# ============== Probing & Tech Detect ==============
def probe_alive(subdomains):
    alive = []
    if not subdomains:
        return alive

    if is_tool_missing("httpx"):
        warn("httpx not found; skipping alive probe (install: https://github.com/projectdiscovery/httpx)")
        return alive

    banner("HTTP Probing (httpx)")
    info(f"Probing {len(subdomains)} candidates")

    try:
        with tempfile.NamedTemporaryFile(mode="w+", delete=True) as f:
            f.write("\n".join(sorted(subdomains)))
            f.flush()
            cmd = ["httpx", "-silent", "-list", f.name]
            def handle(line):
                alive.append(line)
                finding(f"alive: {line}")
            rc = stream_command(cmd, on_line=handle)
            if rc == 0:
                ok(f"httpx probe done. Alive={len(alive)}")
            else:
                warn(f"httpx exited with code {rc}. Alive so far={len(alive)}")
    except Exception as e:
        err(f"Alive probing failed: {e}")

    return alive


def run_tech_scans(alive_subdomains):
    results = []
    if not alive_subdomains:
        return results

    if is_tool_missing("httpx"):
        warn("httpx not found; skipping tech-detect")
        return results

    banner("Technology Detection (httpx -tech-detect)")
    info(f"Fingerprinting {len(alive_subdomains)} targets")

    try:
        with tempfile.NamedTemporaryFile(mode="w+", delete=True) as f:
            f.write("\n".join(alive_subdomains))
            f.flush()
            cmd = ["httpx", "-tech-detect", "-silent", "-list", f.name]
            def handle(line):
                # httpx prints: https://host [technology list...]
                results.append(line)
                finding(f"tech: {line}")
            rc = stream_command(cmd, on_line=handle)
            if rc == 0:
                ok(f"Tech detect done. Fingerprints={len(results)}")
            else:
                warn(f"httpx tech-detect exited with code {rc}. Fingerprints so far={len(results)}")
    except Exception as e:
        err(f"Tech scans failed: {e}")
    return results


# ============== Pipeline Entry ==============
def process(domain, safe_domain=None):
    banner("Domain Reconnaissance")
    info(f"Target: {domain}")
    info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Subdomain enumeration (streamed)
    banner("Subdomain Enumeration")
    subfinder_results = run_subfinder(domain)
    crtsh_results = run_crtsh(domain)
    dnsbrute_results = run_dnsbrute(domain)

    all_subdomains = sorted(set().union(subfinder_results, crtsh_results, dnsbrute_results))
    ok(f"Total unique subdomains collected: {len(all_subdomains)}")

    # Alive probing (streamed)
    alive = probe_alive(all_subdomains)
    ok(f"Alive subdomains: {len(alive)}")

    # Tech scans (streamed)
    tech_results = run_tech_scans(alive)
    ok(f"Technology fingerprints collected: {len(tech_results)}")

    # Build JSON output
    output = {
        "domain": domain,
        "subdomains": all_subdomains,
        "alive": alive,
        "tech_scans": tech_results
    }

    banner("Summary")
    print(Fore.WHITE + f"Total subdomains found : {len(all_subdomains)}")
    print(Fore.WHITE + f"Alive subdomains       : {len(alive)}")
    print(Fore.WHITE + f"Tech fingerprints      : {len(tech_results)}")
    print(Style.BRIGHT + Fore.CYAN + "\n[✓] Recon complete.\n")

    return output


if __name__ == "__main__":
    if len(sys.argv) < 2:
        err("Usage: python3 recon.py <domain>")
        sys.exit(1)
    domain = sys.argv[1].strip()
    process(domain)
