#!/usr/bin/env python3
import subprocess
import re
import time
import requests
import json
from serpapi.google_search import GoogleSearch
from colorama import Fore, Style, init

# ----------------------------
# Init
# ----------------------------
init(autoreset=True)

TOKENS = [
    #ENTER KEY
]
token_index = 0

API_KEY = "2c7e1ec109b83c09f97a8aaa5e1ff84e1ccde3afcfb85ed4d64fd3c5df08ed8a"

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
PHONE_REGEX = r"\+91[-\s]?\d{10}"   # strict Indian mobile format

DORKS = [
    '"@{domain}" in:file',
    '"{keyword}" aws_access_key_id',
    '"{keyword}" aws_secret_access_key',
    '"{keyword}" api_key',
    '"{keyword}" password',
    '"{keyword}" access_token',
    '"{keyword}" private_key',
    '"{keyword}" username',
]

BASE_PATTERNS = {
    "Github Token": r"(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}",
    "AWS Access ID": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
    "Username": r"(?:username|user|uname|usr)[\'\"\s:=]{0,6}([a-zA-Z][a-zA-Z0-9_]{5,14})",
    "Password": r"(?i)(?:password|passwd|pwd)[\'\"\s:=]{0,6}([A-Za-z][A-Za-z0-9_@#$%^&*]{5,14})"
}

# ----------------------------
# Pretty Print Helpers
# ----------------------------
def banner(title):
    print(f"\n{Fore.MAGENTA}{'═'*15} {title} {'═'*15}{Style.RESET_ALL}")

def log_info(msg):
    print(f"{Fore.CYAN}[➜]{Style.RESET_ALL} {msg}")

def log_success(msg):
    print(f"{Fore.GREEN}[✔]{Style.RESET_ALL} {msg}")

def log_warn(msg):
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

def log_error(msg):
    print(f"{Fore.RED}[✘]{Style.RESET_ALL} {msg}")

# ----------------------------
# GitHub Helpers
# ----------------------------
def get_headers():
    global token_index
    return {"Authorization": f"token {TOKENS[token_index]}"}

def github_search(query, page=1, per_page=20):
    global token_index
    for _ in range(len(TOKENS) + 1):
        url = f"https://api.github.com/search/code?q={query}&page={page}&per_page={per_page}"
        response = requests.get(url, headers=get_headers())
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:  # rate limit
            token_index = (token_index + 1) % len(TOKENS)
            if token_index == 0:
                log_warn("GitHub rate limit reached — sleeping 60s...")
                time.sleep(60)
        else:
            log_error(f"GitHub search failed ({response.status_code})")
            return None
    return None

def extract_patterns(content, domain=None):
    results = {}
    patterns = BASE_PATTERNS.copy()
    if domain:
        patterns["Email"] = rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}"
        patterns["Phone"] = PHONE_REGEX

    for name, regex in patterns.items():
        matches = re.findall(regex, content)
        if matches:
            flat_matches = [m if isinstance(m, str) else m[0] for m in matches]
            results[name] = list(set(flat_matches))
    return results

# ----------------------------
# TheHarvester Integration
# ----------------------------
def run_theharvester(domain):
    import shutil
    if not shutil.which("theHarvester"):
        log_warn("TheHarvester tool not found in PATH. Skipping.")
        return set()

    try:
        cmd = ["theHarvester", "-d", domain, "-b", "bing,duckduckgo,yahoo,crtsh,threatcrowd,hackertarget,github-code"]
        log_info("Running TheHarvester...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
        output = result.stdout + result.stderr
        emails = re.findall(rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}", output)
        log_success(f"TheHarvester found {len(emails)} emails")
        return set(emails)
    except subprocess.TimeoutExpired:
        log_warn("TheHarvester timed out after 150s")
        return set()
    except Exception as e:
        log_error(f"TheHarvester error: {e}")
        return set()

# ----------------------------
# Pastebin via SerpAPI
# ----------------------------
def serpapi_search(query, num=10):
    log_info(f"Searching Pastebin via SerpAPI: {query}")
    params = {"engine": "google", "q": query, "hl": "en", "num": num, "api_key": API_KEY}
    search = GoogleSearch(params)
    results = search.get_dict()
    links = [res.get("link") for res in results.get("organic_results", []) if res.get("link")]
    log_success(f"Found {len(links)} Pastebin results")
    return links

def extract_emails_from_url(url, target_domain):
    try:
        if "pastebin.com/" in url and "/raw/" not in url:
            paste_id = url.split("/")[-1]
            raw_url = f"https://pastebin.com/raw/{paste_id}"
        else:
            raw_url = url
        response = requests.get(raw_url, timeout=10)
        if response.status_code != 200:
            return []
        content = response.text
        found_emails = re.findall(EMAIL_REGEX, content)
        domain_pattern = re.compile(rf"[a-zA-Z0-9._%+-]+@{re.escape(target_domain)}\\b")
        return list(set(filter(domain_pattern.match, found_emails)))
    except Exception:
        return [] 

# ----------------------------
# Pipeline Entry Point
# ----------------------------
def process(domain: str):
    keyword = domain.split(".")[0]
    all_emails, all_phones, usernames = set(), set(), set()
    passwords, found_secrets = [], []

    banner(f"Scanning {domain}")

    # 1. TheHarvester
    banner("TheHarvester")
    all_emails.update(run_theharvester(domain))

    # 2. Pastebin
    banner("Pastebin Leak Search")
    pastebin_urls = serpapi_search(f'site:pastebin.com "{domain}"', num=15)
    for url in pastebin_urls:
        found = extract_emails_from_url(url, domain)
        if found:
            log_success(f"Found {len(found)} emails in {url}")
        all_emails.update(found)

    # 3. GitHub Dorks
    banner("GitHub Dorks Search")
    if not TOKENS:
        log_warn("No GitHub tokens found in TOKENS list. Skipping GitHub dorks.")
    else:
        for dork in DORKS:
            query = dork.format(keyword=keyword, domain=domain)
            log_info(f"Running GitHub dork: {query}")
            page = 1
            while True:
                results = github_search(query, page=page)
                if not results or "items" not in results or not results["items"]:
                    break
                for item in results["items"]:
                    file_url = item["html_url"]
                    raw_url = file_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                    try:
                        file_content = requests.get(raw_url, headers=get_headers(), timeout=10).text
                        leaks = extract_patterns(file_content, domain)
                        for leak_type, values in leaks.items():
                            for v in values:
                                if leak_type == "Email":
                                    all_emails.add(v)
                                elif leak_type == "Phone":
                                    all_phones.add(v)
                                elif leak_type == "Username":
                                    usernames.add(v)
                                elif leak_type == "Password":
                                    passwords.append({"password": v, "source": file_url})
                                else:
                                    found_secrets.append({"type": leak_type, "value": v, "source": file_url})
                    except Exception:
                        log_warn(f"Could not fetch {file_url}")
                page += 1
                if page > 3:
                    break

    # Build result
    result = {
        "domain": domain,
        "emails": sorted(list(all_emails)),
        "phones": sorted(list(all_phones)),
        "usernames": sorted(list(usernames)),
        "passwords": passwords,
        "secrets": found_secrets,
    }

    # Save to <domain>_scan.json
    filename = f"{domain}_scan.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)

    pretty_print(result)
    log_success(f"Results saved to {filename}")
    return result
