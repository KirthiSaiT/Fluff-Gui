#!/usr/bin/env python3
import os
import json
import time
import requests
from serpapi import GoogleSearch
from colorama import init, Fore, Style
from threading import Thread
from itertools import cycle

# ==============================
# CONFIG
# ==============================
API_KEY = "2c7e1ec109b83c09f97a8aaa5e1ff84e1ccde3afcfb85ed4d64fd3c5df08ed8a"  # SerpAPI key

# ==============================
# Loader Animation
# ==============================
def loader_animation(message="Processing..."):
    animation = cycle(["|", "/", "-", "\\"])
    while not stop_loader:
        print(f"\r{Fore.LIGHTYELLOW_EX}{message} {Fore.CYAN}{next(animation)}", end="")
        time.sleep(0.1)
    print("\r" + " " * (len(message) + 4) + "\r", end="")

# ==============================
# Google Dorking
# ==============================
def run_dork(query):
    try:
        search = GoogleSearch({"q": query, "api_key": API_KEY})
        results = search.get_dict()
        dork_results = []
        if "organic_results" in results:
            for res in results["organic_results"]:
                dork_results.append({
                    "title": res.get("title"),
                    "link": res.get("link"),
                })
        return dork_results
    except Exception as e:
        print(Fore.LIGHTRED_EX + f"[!] Google dork failed: {e}")
        return []

def google_dorks(domain):
    print(Style.BRIGHT + Fore.LIGHTBLUE_EX + f"\n=== [ Google Dorking on {domain} ] ===")
    dorks = {
        "Password Files": f'site:{domain} intext:password (ext:xls OR ext:xml OR ext:xlsx OR ext:json OR ext:sql OR ext:log OR ext:bak OR ext:cfg OR ext:ini OR ext:yaml OR ext:yml OR ext:db OR ext:conf)',
        "Confidential Docs": f'site:{domain} ("confidential" OR "internal use only") (ext:doc OR ext:docx OR ext:pptx OR ext:pdf OR ext:txt OR ext:csv OR ext:md OR ext:log)',
        "Archives & Backups": f'site:{domain} (ext:zip OR ext:tar OR ext:gz OR ext:7z OR ext:rar OR ext:bak OR ext:db OR ext:config OR ext:sqlite OR ext:key OR ext:pem OR ext:crt OR ext:asc)'
    }

    results = {}
    for name, query in dorks.items():
        print(Fore.LIGHTGREEN_EX + f"[*] Running dork: {name}")
        res = run_dork(query)
        results[name] = res
        print(Fore.LIGHTYELLOW_EX + f"    [+] Found {len(res)} results\n")
    return results

# ==============================
# Wayback Machine
# ==============================
FILE_EXTENSIONS = [
    ".xls",".xml",".xlsx",".json",".pdf",".sql",".doc",".docx",".pptx",".txt",
    ".zip",".tar",".gz",".bak",".7z",".rar",".log",".db",".config",".csv",".yaml",
    ".pem",".crt",".key",".asc",".bak.zip",".sql.gz",".sql.zip",".sql.tar.gz",".war"
]

def fetch_wayback(domain, file_extensions):
    print(Style.BRIGHT + Fore.LIGHTBLUE_EX + f"\n=== [ Wayback Machine on {domain} ] ===")
    archive_url = f'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&page=/'

    global stop_loader
    stop_loader = False
    loader_thread = Thread(target=loader_animation, args=("Fetching URLs...",))
    loader_thread.start()

    try:
        with requests.get(archive_url, stream=True, timeout=60) as response:
            response.raise_for_status()
            url_list = []
            total_lines = 0
            for line in response.iter_lines(decode_unicode=True):
                if line:
                    url_list.append(line)
                    total_lines += 1
                    if total_lines % 1000 == 0:
                        print(Fore.LIGHTCYAN_EX + f"\r[~] Processed {total_lines} URLs...", end="")

            stop_loader = True
            loader_thread.join()

            print(Fore.LIGHTGREEN_EX + f"\n[+] Fetched {total_lines} URLs from archive.")

            results = {}
            for ext in file_extensions:
                key = ext.strip(".").lower() + "_urls"
                filtered = [url for url in url_list if url.lower().endswith(ext.lower())]
                if filtered:
                    results[key] = filtered
                    print(Fore.LIGHTYELLOW_EX + f"    [+] {len(filtered)} files with {ext}")
            return results

    except Exception as e:
        stop_loader = True
        loader_thread.join()
        print(Fore.LIGHTRED_EX + f"[!] Wayback Machine fetch failed: {e}")
        return {}

# ==============================
# Pipeline Hook
# ==============================
def process(domain):
    return {
        "google_dorks": google_dorks(domain),
        "wayback_machine": fetch_wayback(domain, FILE_EXTENSIONS)
    }

# ==============================
# CLI Mode
# ==============================
if __name__ == "__main__":
    init()

    domain = input(Fore.LIGHTBLUE_EX + "\nEnter the target domain (e.g., example.com): ").strip()
    if not domain:
        print(Fore.LIGHTRED_EX + "[!] Target domain required. Exiting.")
        exit()

    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"\n=== Starting Recon for {domain} ===")

    results = process(domain)

    file_path = f"{domain}_deep.json"
    with open(file_path, "w") as f:
        json.dump(results, f, indent=4)

    print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"\n[✓] Combined results saved to {file_path}")
    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + "\n=== Recon Complete ===\n")
