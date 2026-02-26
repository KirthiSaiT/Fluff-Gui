#!/usr/bin/env python3
"""
photon.py - Web Crawler & OSINT Extractor
Inspired by Photon (https://github.com/s0md3v/Photon)
Extracts: internal/external links, emails, phone numbers,
          JS files, API endpoints, social profiles, secrets in JS,
          forms, comments, robots.txt, sitemap.xml
"""
import requests
import re
import json
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode
from collections import deque
from colorama import Fore, Style, init
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

TIMEOUT = 10
MAX_PAGES   = 50   # Max pages to crawl
MAX_DEPTH   = 3    # Crawl depth

# Regex patterns
PATTERNS = {
    "email":       re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
    "phone":       re.compile(r'(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3,4}[\s\-]?\d{4}'),
    "ipv4":        re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    "jwt":         re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
    "aws_key":     re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret":  re.compile(r'[0-9a-zA-Z/+]{40}'),
    "api_key":     re.compile(r'(?:api[_\-]?key|apikey|api_token|access_token)["\s:=]+["\']?([A-Za-z0-9_\-]{16,64})'),
    "private_key": re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),
    "google_api":  re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "stripe_key":  re.compile(r'(?:sk|pk)_(live|test)_[0-9a-zA-Z]{24,}'),
    "slack_token": re.compile(r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}'),
    "s3_url":      re.compile(r's3[.\-]?amazonaws\.com[/\w\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    "internal_ip": re.compile(r'\b(?:10|127|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'),
}

SOCIAL_PLATFORMS = [
    "twitter.com", "x.com", "linkedin.com", "facebook.com", "instagram.com",
    "github.com", "youtube.com", "tiktok.com", "medium.com", "reddit.com",
    "pinterest.com", "snapchat.com", "telegram.me", "t.me"
]

API_PATTERNS = re.compile(
    r'(?:api|v1|v2|v3|rest|graphql|endpoint)[/\w\-._~:/?#\[\]@!$&\'()*+,;=%]*'
    r'|/api/[^\s"\'<>]+',
    re.IGNORECASE
)

INTERESTING_EXTENSIONS = {
    "js": "JavaScript",
    "json": "JSON",
    "xml": "XML",
    "yaml": "Config",
    "yml": "Config",
    "env": "Environment",
    "config": "Config",
    "bak": "Backup",
    "sql": "Database",
    "log": "Log",
    "txt": "Text",
    "pdf": "Document",
    "csv": "Data",
    "xls": "Spreadsheet",
    "xlsx": "Spreadsheet",
    "zip": "Archive",
    "tar": "Archive",
    "gz": "Archive"
}

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'-'*12}[ {title} ]{'-'*12}{Style.RESET_ALL}")

def ok(msg):      print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):     print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def info(msg):    print(f"{Fore.BLUE}[>]{Style.RESET_ALL} {msg}")
def finding(msg): print(f"{Fore.LIGHTWHITE_EX}> {msg}{Style.RESET_ALL}")
def secret(msg):  print(f"{Fore.RED}[SECRET]{Style.RESET_ALL} {msg}")


def get_headers():
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }


def fetch(url):
    """Fetch a URL and return (text, headers, status)."""
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         headers=get_headers(), allow_redirects=True)
        return r.text or "", dict(r.headers), r.status_code
    except Exception:
        return "", {}, None


def extract_links(base_url, html, domain):
    """Extract all links from HTML, classify as internal/external."""
    internal, external = set(), set()
    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc.replace("www.", "")

    href_pattern = re.compile(r'href=["\']([^"\'#\s]+)["\']', re.IGNORECASE)
    src_pattern  = re.compile(r'src=["\']([^"\'#\s]+)["\']', re.IGNORECASE)

    for match in href_pattern.finditer(html):
        url = match.group(1)
        full_url = urljoin(base_url, url)
        parsed = urlparse(full_url)
        if parsed.scheme in ("http", "https"):
            link_domain = parsed.netloc.replace("www.", "")
            if link_domain == base_domain or link_domain.endswith(f".{base_domain}"):
                internal.add(full_url.split("#")[0])
            else:
                external.add(full_url)

    for match in src_pattern.finditer(html):
        url = match.group(1)
        full_url = urljoin(base_url, url)
        internal.add(full_url)

    return internal, external


def extract_js_files(html, base_url):
    """Find all JS files referenced."""
    js_pattern = re.compile(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
    js_files = set()
    for m in js_pattern.finditer(html):
        url = m.group(1)
        full_url = urljoin(base_url, url)
        js_files.add(full_url)
    return js_files


def extract_forms(html, base_url):
    """Extract all forms and their fields."""
    forms = []
    form_pattern = re.compile(
        r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>(.*?)</form>',
        re.IGNORECASE | re.DOTALL
    )
    input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)

    for m in form_pattern.finditer(html):
        action = m.group(1)
        form_html = m.group(2)
        fields = input_pattern.findall(form_html)
        forms.append({
            "action": urljoin(base_url, action),
            "fields": fields
        })
    return forms


def find_secrets(text, url):
    """Search text for exposed secrets and sensitive data."""
    found = []
    for secret_type, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            unique = list(set(matches[:5]))  # Limit to 5 per type
            for match in unique:
                m = match if isinstance(match, str) else str(match)
                # Filter out false positives
                if secret_type == "phone" and len(m) < 8:
                    continue
                if secret_type == "ipv4" and m.startswith(("0.", "255.")):
                    continue
                found.append({
                    "type": secret_type,
                    "value": m[:100],  # Truncate long values
                    "found_at": url
                })
    return found


def check_special_files(base_url, domain):
    """Check robots.txt, sitemap.xml, security.txt, .well-known."""
    special = {}
    files_to_check = [
        ("/robots.txt", "robots_txt"),
        ("/sitemap.xml", "sitemap"),
        ("/sitemap_index.xml", "sitemap_index"),
        ("/.well-known/security.txt", "security_txt"),
        ("/security.txt", "security_txt_root"),
        ("/.well-known/change-password", "change_password"),
        ("/browserconfig.xml", "browserconfig"),
        ("/crossdomain.xml", "crossdomain_xml"),
        ("/clientaccesspolicy.xml", "clientaccesspolicy"),
    ]

    for path, key in files_to_check:
        url = base_url + path
        text, headers, status = fetch(url)
        if status == 200 and text:
            special[key] = {
                "url": url,
                "size": len(text),
                "content_preview": text[:500]
            }
            ok(f"Found {path} ({len(text)} bytes)")

            # Extract disallowed paths from robots.txt
            if key == "robots_txt":
                disallowed = re.findall(r'Disallow:\s*(\S+)', text, re.IGNORECASE)
                special[key]["disallowed_paths"] = disallowed
                if disallowed:
                    for p in disallowed[:10]:
                        finding(f"Disallowed: {p}")

    return special


def extract_social_links(external_links):
    """Filter external links to find social media profiles."""
    social = {}
    for url in external_links:
        for platform in SOCIAL_PLATFORMS:
            if platform in url:
                if platform not in social:
                    social[platform] = []
                social[platform].append(url)
    return social


def extract_html_comments(html):
    """Extract HTML comments which may contain sensitive info."""
    comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
    comments = []
    for m in comment_pattern.finditer(html):
        content = m.group(1).strip()
        if len(content) > 5 and not content.startswith("[if"):
            comments.append(content[:200])
    return comments[:20]


def process(domain):
    banner("Photon Web Crawler & OSINT Extractor")
    info(f"Target: {domain}")

    base_url = f"https://{domain}"
    parsed_base = urlparse(base_url)

    output = {
        "domain": domain,
        "base_url": base_url,
        "pages_crawled": 0,
        "internal_links": [],
        "external_links": [],
        "js_files": [],
        "emails": [],
        "phones": [],
        "social_profiles": {},
        "forms": [],
        "secrets": [],
        "html_comments": [],
        "interesting_files": {},
        "special_files": {},
        "api_endpoints": [],
        "scanned_at": datetime.now().isoformat()
    }

    # BFS crawler
    queue = deque([(base_url, 0)])
    visited = set()
    all_internal = set()
    all_external = set()
    all_js      = set()
    all_emails  = set()
    all_phones  = set()
    all_secrets = []
    all_comments = []
    all_forms   = []
    api_endpoints = set()
    interesting_files = {}

    banner(f"Crawling (max {MAX_PAGES} pages, depth {MAX_DEPTH})")

    while queue and output["pages_crawled"] < MAX_PAGES:
        current_url, depth = queue.popleft()

        if current_url in visited or depth > MAX_DEPTH:
            continue
        visited.add(current_url)

        info(f"[{output['pages_crawled']+1}/{MAX_PAGES}] {current_url[:80]}")
        text, headers, status = fetch(current_url)

        if not text or status not in (200, 201):
            continue

        output["pages_crawled"] += 1

        # Extract links
        internal, external = extract_links(current_url, text, domain)
        all_internal.update(internal)
        all_external.update(external)

        # Queue new internal URLs
        for link in internal:
            if link not in visited:
                queue.append((link, depth + 1))

        # Extract JS files
        js = extract_js_files(text, current_url)
        all_js.update(js)

        # Extract emails
        emails = PATTERNS["email"].findall(text)
        for e in emails:
            if not e.startswith("example") and "." in e.split("@")[-1]:
                all_emails.add(e)
                finding(f"Email: {e}")

        # Extract secrets
        secrets_found = find_secrets(text, current_url)
        for s in secrets_found:
            if s["type"] not in ("phone", "ipv4"):  # Already handled
                all_secrets.append(s)
                secret(f"{s['type']}: {s['value'][:60]}")

        # Phones
        phones = PATTERNS["phone"].findall(text)
        for p in phones:
            p = p.strip()
            if len(p) >= 8:
                all_phones.add(p)

        # API endpoints
        api_matches = API_PATTERNS.findall(text)
        for ep in api_matches[:10]:
            full_ep = urljoin(current_url, ep)
            if domain in full_ep or ep.startswith("/api"):
                api_endpoints.add(full_ep[:150])

        # HTML comments
        comments = extract_html_comments(text)
        all_comments.extend(comments)

        # Forms
        forms = extract_forms(text, current_url)
        all_forms.extend(forms)

        # Check file extensions
        parsed_url = urlparse(current_url)
        ext = parsed_url.path.split(".")[-1].lower() if "." in parsed_url.path else ""
        if ext in INTERESTING_EXTENSIONS:
            if ext not in interesting_files:
                interesting_files[ext] = []
            interesting_files[ext].append(current_url)

    # Check JS files for secrets
    banner("Scanning JavaScript Files for Secrets")
    for js_url in list(all_js)[:20]:  # Limit to 20 JS files
        info(f"Scanning: {js_url[:80]}")
        text, _, _ = fetch(js_url)
        if text:
            secrets_found = find_secrets(text, js_url)
            all_secrets.extend(secrets_found)

    # Check special files
    banner("Special Files Check")
    output["special_files"] = check_special_files(base_url, domain)

    # Social links
    output["social_profiles"] = extract_social_links(all_external)

    # Populate output
    output["internal_links"] = sorted(list(all_internal))
    output["external_links"] = sorted(list(all_external))
    output["js_files"]       = sorted(list(all_js))
    output["emails"]         = sorted(list(all_emails))
    output["phones"]         = sorted(list(all_phones))
    output["secrets"]        = all_secrets
    output["html_comments"]  = list(set(all_comments))[:30]
    output["forms"]          = all_forms
    output["api_endpoints"]  = sorted(list(api_endpoints))
    output["interesting_files"] = interesting_files

    # Summary
    banner("Photon Summary")
    print(f"  {Fore.WHITE}Pages crawled:    {Fore.CYAN}{output['pages_crawled']}")
    print(f"  {Fore.WHITE}Internal links:   {Fore.CYAN}{len(output['internal_links'])}")
    print(f"  {Fore.WHITE}External links:   {Fore.CYAN}{len(output['external_links'])}")
    print(f"  {Fore.WHITE}JavaScript files: {Fore.CYAN}{len(output['js_files'])}")
    print(f"  {Fore.WHITE}Emails found:     {Fore.GREEN}{len(output['emails'])}")
    print(f"  {Fore.WHITE}Secrets found:    {Fore.RED}{len(output['secrets'])}")
    print(f"  {Fore.WHITE}API endpoints:    {Fore.YELLOW}{len(output['api_endpoints'])}")
    print(f"  {Fore.WHITE}Forms:            {Fore.YELLOW}{len(output['forms'])}")
    if output["emails"]:
        print(f"\n  {Fore.GREEN}Emails:")
        for e in output["emails"][:10]:
            print(f"    → {e}")
    if output["secrets"]:
        print(f"\n  {Fore.RED}Potential Secrets:")
        for s in output["secrets"][:5]:
            print(f"    [{s['type']}] {s['value'][:60]}")

    return output


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    result = process(domain)
    print(json.dumps(result, indent=2, default=str))


