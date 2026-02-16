#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import socket
from urllib.parse import urlparse
from colorama import Fore, Style, init
import urllib3
from serpapi import GoogleSearch
import json
import os
from datetime import datetime

# -------------------------
# Initialize
# -------------------------
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------
# Config
# -------------------------
SERPAPI_KEY = "2c7e1ec109b83c09f97a8aaa5e1ff84e1ccde3afcfb85ed4d64fd3c5df08ed8a"

SOCIAL_DOMAINS = [
    "facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com",
    "youtube.com", "tiktok.com", "pinterest.com", "snapchat.com", "reddit.com",
    "discord.com", "t.me", "whatsapp.com", "wechat.com", "line.me",
    "vk.com", "ok.ru", "tumblr.com", "flickr.com", "medium.com",
    "blogger.com", "blogspot.com", "wordpress.com",
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
    "stackexchange.com", "stackoverflow.com", "dev.to",
    "glassdoor.com", "indeed.com", "angel.co", "producthunt.com",
    "trustpilot.com", "g2.com", "crunchbase.com", "goodfirms.co", "clutch.co",
    "quora.com", "douyin.com", "bilibili.com", "weibo.com",
    "kakao.com", "naver.com", "mix.com"
]

NOT_FOUND_PATTERNS = {
    "instagram.com": ["Sorry, this page isn't available."],
    "twitter.com": ["This account doesn’t exist", "page doesn’t exist"],
    "x.com": ["This account doesn’t exist", "page doesn’t exist"],
    "youtube.com": ["This page isn’t available", "404 Not Found"],
    "linkedin.com": ["Profile Not Found", "page doesn’t exist"],
    "github.com": ["Not Found"],
    "gitlab.com": ["404"],
    "bitbucket.org": ["Page not found"],
    "reddit.com": ["page not found"],
    "tiktok.com": ["Couldn't find this account", "page not available"],
    "pinterest.com": ["Page not found"],
    "snapchat.com": ["Page not found"],
    "medium.com": ["404"],
    "wordpress.com": ["doesn’t exist"],
    "blogspot.com": ["Blog has been removed"],
    "blogger.com": ["Blog has been removed"],
    "discord.com": ["Invite Invalid", "This invite may be expired"],
    "flickr.com": ["404 Not Found"],
    "tumblr.com": ["There's nothing here"],
    "vk.com": ["Page not found"],
    "ok.ru": ["Page not found"],
    "quora.com": ["Page not found"],
    "stackoverflow.com": ["Page Not Found"],
    "stackexchange.com": ["Page Not Found"],
    "dev.to": ["404"],
    "angel.co": ["404"],
    "producthunt.com": ["Page not found"],
    "trustpilot.com": ["Page not found"],
    "g2.com": ["Page not found"],
    "crunchbase.com": ["404"],
    "goodfirms.co": ["404"],
    "clutch.co": ["404"],
    "douyin.com": ["Page not found"],
    "bilibili.com": ["404"],
    "weibo.com": ["does not exist"],
    "kakao.com": ["404"],
    "naver.com": ["not exist"],
    "mix.com": ["Page not found"]

}
# -------------------------
# Pretty Output Helpers
# -------------------------
def banner(title: str):
    print(f"\n{Fore.MAGENTA}{'─'*15} {title} {'─'*15}{Style.RESET_ALL}")

def log_info(msg: str):
    print(f"{Fore.CYAN}[➜] {msg}{Style.RESET_ALL}")

def log_success(msg: str):
    print(f"{Fore.GREEN}[✔] {msg}{Style.RESET_ALL}")

def log_warn(msg: str):
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

def log_error(msg: str):
    print(f"{Fore.RED}[✘] {msg}{Style.RESET_ALL}")

# -------------------------
# Utility Functions
# -------------------------
def normalize_domain(domain):
    if not domain.startswith(("http://", "https://")):
        return "https://" + domain.strip()
    return domain.strip()

def domain_resolves(domain):
    try:
        hostname = domain.replace("https://", "").replace("http://", "").split("/")[0]
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False

def extract_links(domain):
    try:
        log_info(f"Extracting links from {domain}")
        r = requests.get(domain, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        links = [a['href'] for a in soup.find_all('a', href=True)]
        log_success(f"Extracted {len(links)} links")
        return links
    except Exception as e:
        log_warn(f"Error fetching {domain}: {e}")
        return []

def check_social_link(link):
    for social in SOCIAL_DOMAINS:
        if social in link:
            try:
                r = requests.get(link, allow_redirects=True, timeout=20, verify=False)
                if r.status_code == 404:
                    return {"link": link, "status": "DEAD (404)"}
                if social in NOT_FOUND_PATTERNS:
                    for pattern in NOT_FOUND_PATTERNS[social]:
                        if pattern.lower() in r.text.lower():
                            return {"link": link, "status": f"DEAD ({pattern})"}
                return {"link": link, "status": "ALIVE"}
            except Exception:
                return {"link": link, "status": "ERROR (Connection failed)"}
    return None

def search_endpoints(domain, num_results=10):
    query = f'site:{domain} inurl:login OR inurl:register OR inurl:admin'
    params = {"engine": "google", "q": query, "num": num_results, "api_key": SERPAPI_KEY}

    log_info(f"Searching for endpoints via SerpAPI: {query}")
    results = []
    try:
        search = GoogleSearch(params)
        data = search.get_dict()
        if "organic_results" in data:
            for r in data["organic_results"]:
                link = r.get("link")
                if link:
                    results.append(link)
        log_success(f"Found {len(results)} potential endpoints")
    except Exception:
        log_error("SerpAPI search failed, falling back to default endpoints")
    return results

def check_clickjacking(domain):
    banner("Clickjacking Test")
    endpoints = search_endpoints(domain)
    if not endpoints:
        endpoints = [normalize_domain(domain) + "/login", normalize_domain(domain) + "/register"]

    HEADERS = {"User-Agent": "Mozilla/5.0"}
    results = []

    for url in endpoints:
        url = normalize_domain(url) if not urlparse(url).scheme else url
        try:
            resp = requests.get(url, timeout=15, allow_redirects=True, headers=HEADERS, verify=False)
            if 200 <= resp.status_code < 400:
                xfo = resp.headers.get("X-Frame-Options", "")
                csp = resp.headers.get("Content-Security-Policy", "")
                if xfo or "frame-ancestors" in csp.lower():
                    results.append({"url": url, "status": "SAFE"})
                    log_success(f"{url} → SAFE (Protection Enabled)")
                else:
                    results.append({"url": url, "status": "VULNERABLE"})
                    log_error(f"{url} → VULNERABLE (No protection headers)")
            else:
                results.append({"url": url, "status": f"HTTP {resp.status_code}"})
                log_warn(f"{url} → HTTP {resp.status_code}")
        except Exception:
            results.append({"url": url, "status": "ERROR"})
            log_warn(f"{url} → Could not connect")
    return results

# -------------------------
# Pipeline Module
# -------------------------
def process(domain: str):
    domain = normalize_domain(domain)
    banner(f"Scanning {domain}")

    if not domain_resolves(domain):
        log_error(f"Cannot resolve {domain}, skipping...")
        return None

    # Social links
    banner("Social Media Discovery")
    links = extract_links(domain)
    social_results = []
    for link in links:
        res = check_social_link(link)
        if res:
            social_results.append(res)
            color = Fore.GREEN if "ALIVE" in res["status"] else Fore.RED if "DEAD" in res["status"] else Fore.YELLOW
            print("   " + color + f"{res['link']} → {res['status']}")

    if not social_results:
        log_warn(f"No social links found for {domain}")

    # Clickjacking
    cj_results = check_clickjacking(domain)

    # Build result dict
    result = {
        "domain": domain,
        "social_links": social_results,
        "clickjacking": cj_results,
        "scanned_at": datetime.now().isoformat()
    }

    # Save to <domain>_scan.json
    filename = f"{domain.replace('https://', '').replace('http://', '').split('/')[0]}_scan.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)

    log_success(f"Results saved to {filename}")
    return result

# -------------------------
# Entry
# -------------------------
def main():
    print(Fore.LIGHTCYAN_EX + "\n🌐 Web Recon Scanner v2.0")
    print(Fore.LIGHTWHITE_EX + "-------------------------------------------")
    domains = input(Fore.CYAN + "Enter domains/subdomains (comma-separated): ").split(",")
    for d in domains:
        process(d.strip())

if __name__ == "__main__":
    main()
