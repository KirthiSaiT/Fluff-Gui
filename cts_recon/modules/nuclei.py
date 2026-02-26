#!/usr/bin/env python3
"""
nuclei.py - Nuclei Vulnerability Scanner Integration
Runs community templates: cves, misconfiguration, exposures, takeovers, default-logins
Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
Update templates: nuclei -update-templates
"""
import subprocess
import shutil
import json
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Template categories to run (from least to most aggressive)
TEMPLATE_TAGS = [
    "exposure",
    "misconfiguration",
    "takeover",
    "default-login",
    "cve",
    "panel",
    "tech",
]

SEVERITY_COLOR = {
    "info":     Fore.CYAN,
    "low":      Fore.BLUE,
    "medium":   Fore.YELLOW,
    "high":     Fore.RED,
    "critical": Fore.MAGENTA,
    "unknown":  Fore.WHITE,
}

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'─'*12}[ {title} ]{'─'*12}{Style.RESET_ALL}")

def ok(msg):      print(f"{Fore.GREEN}[✔]{Style.RESET_ALL} {msg}")
def warn(msg):    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):     print(f"{Fore.RED}[✘]{Style.RESET_ALL} {msg}")
def info(msg):    print(f"{Fore.BLUE}[➜]{Style.RESET_ALL} {msg}")
def finding(sev, msg): print(f"{SEVERITY_COLOR.get(sev, Fore.WHITE)}[{sev.upper()}]{Style.RESET_ALL} {msg}")


def is_nuclei_installed():
    return shutil.which("nuclei") is not None


def update_templates():
    """Update nuclei templates silently."""
    try:
        subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=True, text=True, timeout=120
        )
        ok("Nuclei templates updated")
    except Exception:
        warn("Could not update templates — using existing ones")


def run_nuclei(target, tags):
    """Run nuclei against target with specified template tags."""
    findings = []

    cmd = [
        "nuclei",
        "-u", target,
        "-tags", ",".join(tags),
        "-json",
        "-silent",
        "-no-color",
        "-timeout", "10",
        "-retries", "1",
        "-rate-limit", "50",
    ]

    info(f"Running nuclei on {target} with tags: {tags}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=300
        )

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                sev = data.get("info", {}).get("severity", "unknown").lower()
                name = data.get("info", {}).get("name", "Unknown")
                matched = data.get("matched-at", "")
                template_id = data.get("template-id", "")
                description = data.get("info", {}).get("description", "")
                tags_found = data.get("info", {}).get("tags", [])
                reference = data.get("info", {}).get("reference", [])

                finding_obj = {
                    "template_id": template_id,
                    "name": name,
                    "severity": sev,
                    "matched_at": matched,
                    "description": description,
                    "tags": tags_found if isinstance(tags_found, list) else [tags_found],
                    "reference": reference if isinstance(reference, list) else [reference],
                    "raw": data
                }
                findings.append(finding_obj)
                finding(sev, f"{name} → {matched}")

            except json.JSONDecodeError:
                # nuclei sometimes prints non-JSON status lines
                if line and not line.startswith("["):
                    warn(f"Non-JSON output: {line[:100]}")

        proc.wait()
        ok(f"Nuclei scan complete. Findings: {len(findings)}")

    except subprocess.TimeoutExpired:
        warn("Nuclei timed out after 300s — partial results returned")
    except FileNotFoundError:
        err("nuclei binary not found in PATH")
    except Exception as e:
        err(f"Nuclei execution error: {e}")

    return findings


def summarize_findings(findings):
    """Group findings by severity."""
    summary = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in summary:
            summary[sev].append(f["name"])
    return summary


def process(domain):
    banner("Nuclei Vulnerability Scanner")

    if not is_nuclei_installed():
        warn("nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        warn("Then run: nuclei -update-templates")
        return {
            "error": "nuclei not installed",
            "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "findings": []
        }

    target = f"https://{domain}"
    info(f"Target: {target}")

    # Update templates
    update_templates()

    # Run scan
    banner("Running Templates")
    findings = run_nuclei(target, TEMPLATE_TAGS)

    # Also try http
    http_findings = []
    if not any(f.get("matched_at", "").startswith("http://") for f in findings):
        http_target = f"http://{domain}"
        info(f"Also scanning {http_target}...")
        http_findings = run_nuclei(http_target, ["exposure", "misconfiguration", "panel"])

    all_findings = findings + http_findings
    summary = summarize_findings(all_findings)

    output = {
        "domain": domain,
        "target": target,
        "findings": all_findings,
        "summary": summary,
        "total": len(all_findings),
        "scanned_at": datetime.now().isoformat()
    }

    banner("Nuclei Summary")
    print(f"  {Fore.MAGENTA}Critical: {len(summary['critical'])}")
    print(f"  {Fore.RED}High:     {len(summary['high'])}")
    print(f"  {Fore.YELLOW}Medium:   {len(summary['medium'])}")
    print(f"  {Fore.BLUE}Low:      {len(summary['low'])}")
    print(f"  {Fore.CYAN}Info:     {len(summary['info'])}")
    print(f"  {Fore.WHITE}Total:    {len(all_findings)}")

    return output


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    result = process(domain)
    # Print summary only in CLI mode
    print(json.dumps({k: v for k, v in result.items() if k != "raw"}, indent=2, default=str))
