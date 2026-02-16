import json
import os
import io
import datetime
from flask import (
    Flask,
    render_template,
    jsonify,
    send_file,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from werkzeug.utils import secure_filename
from collections import defaultdict

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

app = Flask(__name__)
app.secret_key = "dev-secret"

# --- Config ---
BACKEND_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "backend", "output")
os.makedirs(BACKEND_OUTPUT_DIR, exist_ok=True)

# --- Module Keys ---
MODULE_KEYS = {
    "subdomain": ["subdomain", "subdomains", "alive"],
    "subdomain-discovery": ["subdomains", "alive", "subdomain_discovery"],
    "port-service-scanning": [
        "ports",
        "services",
        "port_service_scanning",
        "portscan",
        "shodan_nmap",
        "shodan",
    ],
    "public-data-scraping": [
        "emails",
        "phones",
        "usernames",
        "passwords",
        "secrets",
        "public_data_scraping",
        "scrapping",
    ],
    # Use hyphenated slug to match routes; include synonyms
    "vulnerable_assessment": [
        "vulnerabilities",
        "vulns",
        "vulnerability_assessment",
        "vulnerability-assessment",
        # sensitive / google dorks
        "sensitive",
        "google_dorks",
        "google-dorks",
        "password_dork",
        "password-dorks",
        "password_dorks",
        "confidential_dork",
        "confidential-dorks",
        "uncommon_ext_dork",
        "uncommon-ext-dork",
        "uncommon_ext_dorks",
        # wayback machine buckets (all 7)
        "wayback",
        "wayback_machine",
        "wayback-machine",
        "xls_urls",
        "xml_urls",
        "xlsx_urls",
        "json_urls",
        "pdf_urls",
        "php_urls",
        "war_urls",
        # broken links / risk / social links
        "risk",
        "broken_links",
        "broken-link",
        "broken-links",
        "social_links",
        "social-link",
        "social-links",
        "domain",
        # vulnerable urls (gf results)
        "vulnerable_urls",
        "vulnerable-urls",
        "gf_results",
        "gf-results",
        "xss",
        "ssrf",
        "sqli",
        "rce",
        "redirect",
        "lfi",
        "ssti",
        "idor",
        "rfi",
    ],
    "technology-profile-mapping": [
        "bucket",
        "Sbucket",
        "whois",
        "ip_ranges",
        "Google_Cloud",
        "AWS_S3",
        "Azure",
        "Oracle_Cloud",
        "DigitalOcean",
        "buckets",
        "vulnerablities",
        "shodan_nmap",
        "cve_ids",
        "tech_scans",
        "shodan",
        "phishing_vectors",
        "spf",
        "dmarc",
        "dkim",
        "emailsecurity",
        "risk",
        "clickjacking",
    ],
}


def load_results(scan_type=None, domain=None):
    """
    Load scan results from backend/output/.
    Supports {domain}_{scan_type}.json classification.
    
    Args:
        scan_type: "lite" or "deep" (optional)
        domain: target domain (optional, to pick correct file)
    
    Returns:
        dict: Parsed JSON content or {} if not found.
    """
    files = os.listdir(BACKEND_OUTPUT_DIR)

    # --- Case 1: Explicit domain + scan_type ---
    if scan_type and domain:
        match = f"{domain}_{scan_type}.json"
        filepath = os.path.join(BACKEND_OUTPUT_DIR, match)
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}  # domain-specific file not found

    # --- Case 2: Only scan_type given (lite/deep) ---
    if scan_type:
        candidates = [f for f in files if f.endswith(f"_{scan_type}.json")]
        if candidates:
            latest = max(
                candidates,
                key=lambda f: os.path.getmtime(os.path.join(BACKEND_OUTPUT_DIR, f))
            )
            filepath = os.path.join(BACKEND_OUTPUT_DIR, latest)
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    # --- Case 3: No scan_type → auto-pick latest .json ---
    candidates = [f for f in files if f.endswith(".json")]
    if candidates:
        latest = max(
            candidates,
            key=lambda f: os.path.getmtime(os.path.join(BACKEND_OUTPUT_DIR, f))
        )
        filepath = os.path.join(BACKEND_OUTPUT_DIR, latest)
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    return {}


def get_spiderfoot_url():
    """Read SpiderFoot URL from backend/output/spiderfoot_url.txt"""
    url_file = os.path.join(BACKEND_OUTPUT_DIR, "spiderfoot_url.txt")
    if os.path.exists(url_file):
        with open(url_file, "r") as f:
            return f.read().strip()
    return None


def extract_module(results: dict, module_slug: str):
    """Extract and merge module-specific data using MODULE_KEYS"""
    keys = MODULE_KEYS.get(module_slug, [])
    data = {}

    def merge_dict(target, source):
        for k, v in source.items():
            if k not in target:
                # deep copy primitive/dict/list
                target[k] = v
            else:
                # merge lists
                if isinstance(v, list) and isinstance(target[k], list):
                    target[k].extend(v)
                # merge dicts
                elif isinstance(v, dict) and isinstance(target[k], dict):
                    merge_dict(target[k], v)
                # fallback: overwrite
                else:
                    target[k] = v

    # top-level keys
    for k in keys:
        if k in results:
            merge_dict(data, {k: results[k]})

    # nested dicts (one level deep)
    for _, v in results.items():
        if isinstance(v, dict):
            for kk in keys:
                if kk in v:
                    merge_dict(data, {kk: v[kk]})

    return data


def _safe_dedupe_list(lst):
    """Return list with duplicates removed while handling unhashable items."""
    seen = set()
    out = []
    for item in lst:
        try:
            key = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
        except Exception:
            # fallback to string representation
            key = str(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def normalize_subdomain_data(module_data):
    if not isinstance(module_data, dict):
        return {"alive": [], "subdomains": [], "alive_count": 0, "subdomains_count": 0}

    alive = module_data.get("alive", [])
    subs = module_data.get("subdomains", [])

    if not isinstance(alive, list):
        alive = [alive]
    if not isinstance(subs, list):
        subs = [subs]

    return {
        "alive": alive,
        "subdomains": subs,
        "alive_count": len(alive),
        "subdomains_count": len(subs),
    }


def normalize_portscan_data(module_data):
    if not isinstance(module_data, dict):
        return {
            "all_results": [],
            "ports": [],
            "ports_with_vulns": [],
            "services": [],
            "ports_count": 0,
            "services_count": 0,
        }

    ports = []
    ports_with_vulns = []
    services = []
    all_results_raw = []

    # Direct ports/services from top-level module_data
    ports.extend(module_data.get("ports", []))
    services.extend(module_data.get("services", []))

    # --- Handle Shodan formats ---
    if "shodan" in module_data and isinstance(module_data["shodan"], dict):
        shodan_nmap = module_data["shodan"].get("shodan_nmap", [])
    elif "shodan_nmap" in module_data and isinstance(module_data["shodan_nmap"], list):
        shodan_nmap = module_data["shodan_nmap"]
    else:
        shodan_nmap = []

    # Flatten raw results
    for item in shodan_nmap:
        item_ports = item.get("ports", [])
        item_vulns = item.get("vulnerabilities", [])

        for port in item_ports:
            all_results_raw.append({
                "ip": item.get("ip"),
                "port": port,
                "org": item.get("org"),
                "hostnames": item.get("hostnames", []),
                "location": item.get("location", {}),
                "vulnerabilities": item_vulns,
            })
            ports.append(port)

        if item_vulns:
            ports_with_vulns.extend(item_ports)

    # --- Group results by IP with deduplication ---
    grouped = defaultdict(lambda: {"ip": "", "ports": [], "org": "", "hostnames": [], "location": {}, "vulnerabilities": []})

    for res in all_results_raw:
        ip = res.get("ip", "N/A")
        grouped[ip]["ip"] = ip
        # append ports and dedupe later
        grouped[ip]["ports"].extend([res.get("port")])
        grouped[ip]["org"] = res.get("org") or grouped[ip]["org"]

        # Deduplicate hostnames safely
        grouped[ip]["hostnames"].extend(res.get("hostnames", []))

        # Location (keep the first non-empty one)
        if res.get("location"):
            grouped[ip]["location"] = res.get("location")

        # Append vulnerabilities (could be dicts)
        grouped[ip]["vulnerabilities"].extend(res.get("vulnerabilities", []))

    # Final pass to unique lists
    all_results = []
    for ip, vals in grouped.items():
        vals["ports"] = list(dict.fromkeys([p for p in vals["ports"] if p is not None]))
        vals["hostnames"] = _safe_dedupe_list(vals["hostnames"])
        vals["vulnerabilities"] = _safe_dedupe_list(vals["vulnerabilities"])
        all_results.append(vals)

    return {
        "ports": ports,
        "ports_with_vulns": ports_with_vulns,
        "services": services,
        "all_results": all_results,
        "ports_count": len(ports),
        "services_count": len(services),
    }


def normalize_public_data(module_data):
    if not isinstance(module_data, dict):
        return {
            "emails": [],
            "phones": [],
            "usernames": [],
            "passwords": [],
            "secrets": [],
            "emails_count": 0,
            "phones_count": 0,
            "usernames_count": 0,
            "passwords_count": 0,
            "secrets_count": 0
        }

    emails = module_data.get("emails", [])
    phones = module_data.get("phones", [])
    usernames = module_data.get("usernames", [])
    passwords = module_data.get("passwords", [])
    secrets = module_data.get("secrets", [])

    return {
        "emails": emails,
        "phones": phones,
        "usernames": usernames,
        "passwords": passwords,
        "secrets": secrets,
        "emails_count": len(emails),
        "phones_count": len(phones),
        "usernames_count": len(usernames),
        "passwords_count": len(passwords),
        "secrets_count": len(secrets),
    }


import re
from collections import Counter

# Assuming defaultdict is already imported from the top of the file
# from collections import defaultdict

def normalize_techprofile_data(module_data):
    if not isinstance(module_data, dict):
        return {}

    # --- IP Ranges ---
    ip_ranges = []
    for entry in module_data.get("whois", []):
        ip = entry.get("ip")
        netrange, cidr = None, None
        for line in entry.get("whois", []):
            line_lower = line.lower()
            if line_lower.startswith("netrange"):
                netrange = line.split(":", 1)[1].strip()
            elif line_lower.startswith("cidr"):
                cidr = line.split(":", 1)[1].strip()
        ip_ranges.append({"ip": ip, "netrange": netrange, "cidr": cidr})

    # --- Multicloud (instead of S3 Buckets) ---
    multicloud_raw = module_data.get("bucket", {}) or {}
    multicloud = {}

    cloud_keys = ["Google_Cloud", "AWS_S3", "Azure", "Oracle_Cloud", "DigitalOcean"]
    for ck in cloud_keys:
        items = multicloud_raw.get(ck, []) or []
        multicloud[ck] = items

    # --- CVEs ---
    raw_cves = []
    for cve in module_data.get("cve_ids", []):
        if isinstance(cve, str):
            raw_cves.append({"cve": cve, "cvss": None, "hostnames": []})
        elif isinstance(cve, dict) and "cve" in cve:
            raw_cves.append({
                "cve": cve["cve"],
                "cvss": cve.get("cvss"),
                "hostnames": cve.get("hostnames", [])
            })

    # Shodan CVEs
    shodan_data = module_data.get("shodan", {})

    def extract_shodan_vulns(data):
        vulns = []
        if isinstance(data, dict):
            shodan_nmap = data.get("shodan_nmap", [])
            if isinstance(shodan_nmap, dict):
                for v in shodan_nmap.get("vulnerabilities", []):
                    if isinstance(v, dict):  # ADDED CHECK
                        vulns.append({
                            "cve": v.get("cve"),
                            "cvss": v.get("cvss"),
                            "hostnames": shodan_nmap.get("hostnames", [])
                        })
            elif isinstance(shodan_nmap, list):
                for entry in shodan_nmap:
                    if isinstance(entry, dict):
                        for v in entry.get("vulnerabilities", []):
                            if isinstance(v, dict):  # ADDED CHECK
                                vulns.append({
                                    "cve": v.get("cve"),
                                    "cvss": v.get("cvss"),
                                    "hostnames": entry.get("hostnames", [])
                                })
        elif isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    vulns.extend(extract_shodan_vulns(entry))
        return vulns

    raw_cves.extend(extract_shodan_vulns(shodan_data))

    cve_ids = []
    for cve in raw_cves:
        if isinstance(cve, str) and cve.startswith("CVE-"):
            cve_ids.append({"cve": cve, "cvss": None, "hostnames": []})
        elif isinstance(cve, dict) and "cve" in cve and cve["cve"].startswith("CVE-"):
            cve_ids.append({
                "cve": cve["cve"],
                "cvss": cve.get("cvss"),
                "hostnames": cve.get("hostnames", [])
            })

    module_data["cve_ids"] = cve_ids

    # --- Tech Stack ---
    tech_stack_raw = module_data.get("tech_scans", [])
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    tech_stack = []
    for t in tech_stack_raw:
        # Try to split into subdomain + stack info
        match = re.match(r'^(https?://\S+)\s+(.*)$', t)
        if match:
            url, stack_raw = match.groups()
            # Clean ANSI sequences
            clean_stack = ansi_escape.sub('', stack_raw).strip()
            # Remove brackets if they exist
            clean_stack = clean_stack.strip("[]")
            stack_list = [s.strip() for s in clean_stack.split(",") if s.strip()]
            tech_stack.append({"subdomain": url, "stack": stack_list})
        else:
            tech_stack.append({"subdomain": t.strip(), "stack": []})

    # Assuming remove_duplicates is defined earlier in the code
    # def remove_duplicates(lst):
    #     seen = set()
    #     unique = []
    #     for item in lst:
    #         try:
    #             key = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
    #         except Exception:
    #             key = str(item)
    #         if key not in seen:
    #             seen.add(key)
    #             unique.append(item)
    #     return unique

    tech_stack = _safe_dedupe_list(tech_stack) # Using the imported/defined _safe_dedupe_list

    tech_list = []
    for t in tech_stack:
        for tech in t["stack"]:
            if tech:
                tech_list.append(tech)

    tech_counts = dict(Counter(tech_list))

    # --- Email Security ---
    phishing_vectors = {"emailsecurity": {"spf": [], "dmarc": [], "dkim": []}, "clickjacking": []}
    emailsec = module_data.get("emailsecurity", {})
    while isinstance(emailsec, dict) and "emailsecurity" in emailsec:
        emailsec = emailsec["emailsecurity"]

    if isinstance(emailsec, dict):
        spf_list = []
        for x in emailsec.get("spf", []):
            if isinstance(x, dict):
                spf_list.append({"status": x.get("status", ""), "detail": x.get("detail", "")})
            elif isinstance(x, str):
                spf_list.append({"status": x, "detail": ""})
        phishing_vectors["emailsecurity"]["spf"] = _safe_dedupe_list(spf_list) # Using the imported/defined _safe_dedupe_list

        dmarc_list = []
        for x in emailsec.get("dmarc", []):
            if isinstance(x, dict):
                dmarc_list.append({
                    "status": x.get("status", ""),
                    "full_record": x.get("full_record", ""),
                    "main_policy": x.get("main_policy", ""),
                    "sub_policy": x.get("sub_policy", "")
                })
            elif isinstance(x, str):
                dmarc_list.append({
                    "status": x,
                    "full_record": "",
                    "main_policy": "",
                    "sub_policy": ""
                })
        phishing_vectors["emailsecurity"]["dmarc"] = _safe_dedupe_list(dmarc_list) # Using the imported/defined _safe_dedupe_list

        dkim_list = []
        for x in emailsec.get("dkim", []):
            if isinstance(x, dict):
                dkim_list.append({
                    "status": x.get("status", ""),
                    "selector": x.get("selector", ""),
                    "record": x.get("record", "")
                })
            elif isinstance(x, str):
                dkim_list.append({"status": x, "selector": "", "record": ""})
        phishing_vectors["emailsecurity"]["dkim"] = _safe_dedupe_list(dkim_list) # Using the imported/defined _safe_dedupe_list

    risk = module_data.get("risk", {})
    phishing_vectors["clickjacking"] = risk.get("clickjacking", []) if isinstance(risk.get("clickjacking"), list) else []

    return {
        "ip_ranges": ip_ranges,
        "multicloud": multicloud,
        "cve_ids": cve_ids,
        "tech_stack": tech_stack,
        "phishing_vectors": phishing_vectors,
        "tech_counts": tech_counts,
        "ip_ranges_count": len(ip_ranges),
        "multicloud_count": sum(len(v) for v in multicloud.values()),
        "cve_ids_count": len(cve_ids),
        "tech_stack_count": len(tech_stack)
    }


def normalize_vulnerable_assessment(data: dict) -> dict:
    """
    Normalize vulnerable_assessment data structure for template rendering.
    Ensures all keys exist with safe defaults.
    """
    if not isinstance(data, dict):
        return {
            "sensitive": {
                "google_dorks": {
                    "password_dork": [],
                    "confidential_dork": [],
                    "uncommon_ext_dork": []
                },
                "wayback_machine": {
                    "xls_urls": [],
                    "xml_urls": [],
                    "xlsx_urls": [],
                    "json_urls": [],
                    "pdf_urls": [],
                    "php_urls": [],
                    "war_urls": []
                }
            },
            "risk": {
                "domain": "",
                "social_links": []
            },
            "vulnerable_urls": {
                "gf_results": {
                    "xss": [],
                    "ssrf": [],
                    "sqli": [],
                    "rce": [],
                    "redirect": [],
                    "lfi": [],
                    "ssti": [],
                    "idor": [],
                    "rfi": [],
                    "counts": {}
                }
            }
        }

    # --- Sensitive ---
    sensitive = data.get("sensitive", {}) or {}

    google_dorks = sensitive.get("google_dorks", {}) or {}
    normalized_google_dorks = {
        "password_dork": google_dorks.get("password_dork", []) or [],
        "confidential_dork": google_dorks.get("confidential_dork", []) or [],
        "uncommon_ext_dork": google_dorks.get("uncommon_ext_dork", []) or [],
    }

    wayback = sensitive.get("wayback_machine", {}) or {}
    normalized_wayback = {
        "xls_urls": wayback.get("xls_urls", []) or [],
        "xml_urls": wayback.get("xml_urls", []) or [],
        "xlsx_urls": wayback.get("xlsx_urls", []) or [],
        "json_urls": wayback.get("json_urls", []) or [],
        "pdf_urls": wayback.get("pdf_urls", []) or [],
        "php_urls": wayback.get("php_urls", []) or [],
        "war_urls": wayback.get("war_urls", []) or [],
    }

    # --- Risk ---
    risk = data.get("risk", {}) or {}
    normalized_risk = {
        "domain": risk.get("domain", ""),
        "social_links": risk.get("social_links", []) or [],
    }

    # --- Vulnerable URLs (GF Results only) ---
    vulnerable_urls = data.get("vulnerable_urls", {}) or {}
    gf = vulnerable_urls.get("gf_results", {}) or {}

    categories = ["xss", "ssrf", "sqli", "rce", "redirect", "lfi", "ssti", "idor", "rfi"]
    normalized_gf = {}
    counts = {}

    for cat in categories:
        urls = gf.get(cat, []) or []
        normalized_gf[cat] = urls
        counts[cat] = len(urls)

    normalized_gf["counts"] = counts

    return {
        "sensitive": {
            "google_dorks": normalized_google_dorks,
            "wayback_machine": normalized_wayback,
        },
        "risk": normalized_risk,
        "vulnerable_urls": {
            "gf_results": normalized_gf
        }
    }


# --- NEW FUNCTION ---
def get_module_data(slug):
    results = load_results("deep")  # always read from deep scan
    module_raw = extract_module(results, slug)

    # Normalize depending on module
    if slug in ["subdomain", "subdomain-discovery"]:
        return normalize_subdomain_data(module_raw)
    elif slug == "port-service-scanning":
        return normalize_portscan_data(module_raw)
    elif slug == "public-data-scraping":
        return normalize_public_data(module_raw)
    elif slug == "technology-profile-mapping":
        return normalize_techprofile_data(module_raw)
    elif slug in ["vulnerable_assessment"]:
        return normalize_vulnerable_assessment(module_raw)
    else:
        # Default fallback (just raw dict)
        return module_raw


# --- Routes ---
@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/scan-options")
def scan_options():
    return render_template("scan_options.html")


@app.route("/light")
def light_scan():
    """Light Scan now shows only SpiderFoot URL (iframe)"""
    spiderfoot_url = get_spiderfoot_url()
    return render_template("light.html", spiderfoot_url=spiderfoot_url)


@app.route("/deep")
def deep_scan():
    results = load_results("deep")
    has_results = bool(results)
    return render_template("deep.html", has_results=has_results)


@app.route("/module/<slug>")
def module_page(slug):
    module_data = get_module_data(slug)

    if slug in ["subdomain", "subdomain-discovery"]:
        template = "subdomain.html"
    elif slug == "port-service-scanning":
        template = "portscan.html"
    elif slug == "public-data-scraping":
        template = "scrap.html"
    elif slug == "technology-profile-mapping":
        template = "tech.html"
    elif slug in ["vulnerable_assessment"]:
        template = "vuln.html"
    else:
        template = "fallback.html"

    return render_template(template, module_data=module_data, slug=slug)


@app.route("/api/vuln/<section>")
def vuln_data(section):
    results = get_module_data("vulnerable_assessment")

    # Google Dorks
    if section in ["password_dork", "confidential_dork", "uncommon_ext_dork"]:
        return jsonify(results.get("sensitive", {}).get("google_dorks", {}).get(section, []))

    # Wayback
    if section in results.get("sensitive", {}).get("wayback_machine", {}):
        return jsonify(results["sensitive"]["wayback_machine"][section])

    # Broken Links / Social Links
    if section == "social_links":
        return jsonify(results.get("risk", {}).get("social_links", []))

    # Vulnerable URLs (GF Results)
    return jsonify(
        results.get("vulnerable_urls", {}).get("gf_results", {}).get(section, [])
    )
    return jsonify([])


@app.route("/api/results/<scan_type>")
def api_results(scan_type):
    return jsonify(load_results(scan_type))


@app.route("/api/spiderfoot-url")
def api_spiderfoot_url():
    url = get_spiderfoot_url()
    if url:
        return jsonify({"url": url})
    return jsonify({"error": "SpiderFoot URL not found"}), 404


@app.route("/spiderfoot")
def spiderfoot_ui():
    return render_template("spiderfoot.html")


@app.route("/report")
def report():
    results = load_results("deep")
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    mem = io.BytesIO(json.dumps(results, indent=2).encode("utf-8"))
    mem.seek(0)
    return send_file(
        mem,
        as_attachment=True,
        download_name=f"recon_report_{ts}.json",
        mimetype="application/json",
    )


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file part")
        return redirect(url_for("scan_options"))

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("scan_options"))

    to = request.args.get("to", "deep")  # only "deep" supported
    if to == "light":
        flash("Upload is not available for Light Scan")
        return redirect(url_for("light_scan"))

    # Always overwrite deep_scan.json
    save_path = os.path.join(BACKEND_OUTPUT_DIR, "deep_scan.json")
    file.save(save_path)

    # Validate JSON
    try:
        with open(save_path, "r", encoding="utf-8") as f:
            json.load(f)
    except Exception as e:
        flash(f"Error parsing JSON: {e}")
        return redirect(url_for("deep_scan"))

    # Store uploaded filename in session for deep_scan_view
    session['latest_file'] = "deep_scan.json"

    flash("File uploaded successfully! The latest scan will now be used.")
    return redirect(url_for("deep_scan"))


@app.route("/deep_scan")
def deep_scan_view():  # renamed function
    latest_file = session.get('latest_file', "deep_scan.json")
    file_path = os.path.join(BACKEND_OUTPUT_DIR, latest_file)

    if not os.path.exists(file_path):
        flash("No scan file uploaded yet!")
        return render_template("deep_scan.html", module_data={"all_results": []})

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # default to portscan normalization for example
        module_data = normalize_portscan_data(data)
    except Exception as e:
        flash(f"Error loading scan file: {e}")
        module_data = {"all_results": []}

    return render_template("deep_scan.html", module_data=module_data)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)