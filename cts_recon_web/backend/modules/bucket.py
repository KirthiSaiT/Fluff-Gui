#!/usr/bin/env python3
import os
import re
import json
import time
import subprocess
from urllib.parse import urlparse
from datetime import datetime
from serpapi import GoogleSearch
from colorama import Fore, Style, init

# ---- Optional Cloud SDKs ----
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None

try:
    from google.cloud import storage as gcs_storage
except ImportError:
    gcs_storage = None

try:
    from azure.storage.blob import BlobServiceClient
except ImportError:
    BlobServiceClient = None

init(autoreset=True)

API_KEY = "4931a0bad6b640deb2423b8749df8f045956e22e55d86a6b1c23bb4558d4dd3e"

# -------------------
# DNS + WHOIS Helpers
# -------------------
def get_dns_records(domain):
    print(Style.BRIGHT + Fore.LIGHTBLUE_EX + f"\n=== [ DNS Lookup for {domain} ] ===")
    try:
        # Use nslookup as dig is not standard on Windows
        result = subprocess.run(
            ["nslookup", domain],
            capture_output=True, text=True, check=True
        )
        ips = []
        for line in result.stdout.splitlines():
             if "Address:" in line:
                 parts = line.split(":")
                 if len(parts) > 1:
                     ip = parts[1].strip()
                     # Filter out local DNS server IP usually printed first
                     if not ip.startswith("192.168") and not ip.startswith("127.") and not ip.startswith("10."):
                        ips.append(ip)
        
        if ips:
            for ip in ips:
                print(Fore.LIGHTGREEN_EX + f"[+] {domain} resolves to {ip}")
        else:
            print(Fore.LIGHTYELLOW_EX + "[!] No A records found.")
        return list(set(ips))
    except Exception as e:
        print(Fore.LIGHTRED_EX + f"[!] DNS lookup failed: {e}")
        return []

def get_whois_info(ip):
    try:
        import whois
        w = whois.whois(ip)
        print(Fore.LIGHTCYAN_EX + f"[*] WHOIS info for {ip}:")
        # specific fields or just raw
        if w.text:
             # limit output lines
            lines = w.text.splitlines()[:20]
            for line in lines:
                print(Fore.LIGHTGREEN_EX + f"    {line}")
            return lines
        else:
             print(Fore.LIGHTYELLOW_EX + f"[!] No text in WHOIS record for {ip}")
             return []
    except ImportError:
        print(Fore.LIGHTRED_EX + "[!] python-whois not installed. Install with: pip install python-whois")
        return []
    except Exception as e:
        print(Fore.LIGHTYELLOW_EX + f"[!] WHOIS lookup failed for {ip}: {e}")
        return []

# -------------------
# Bucket Extraction Helpers
# -------------------
def extract_s3_bucket(url):
    parsed = urlparse(url)
    host = parsed.netloc
    if host.endswith(".s3.amazonaws.com"):
        return host.split(".s3.amazonaws.com")[0]
    elif ".s3." in host:
        return host.split(".s3.")[0]
    return None

def extract_gcs_bucket(url):
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path.strip("/").split("/")
    if "storage.googleapis.com" in host and path:
        return path[0]
    match = re.match(r"^([a-z0-9][a-z0-9._-]*[a-z0-9])\.storage\.googleapis\.com$", host)
    return match.group(1) if match else None

def extract_azure_bucket(url):
    parsed = urlparse(url)
    match = re.match(r"^([a-z0-9-]+)\.blob\.core\.windows\.net$", parsed.netloc)
    return match.group(1) if match else None

def extract_do_bucket(url):
    parsed = urlparse(url)
    match = re.match(r"^([a-z0-9-]+)\.nyc3\.digitaloceanspaces\.com$", parsed.netloc)
    return match.group(1) if match else None

def extract_oracle_bucket(url):
    parsed = urlparse(url)
    match = re.match(r"^([a-z0-9-]+)\.objectstorage\.[a-z0-9-]+\.oraclecloud\.com$", parsed.netloc)
    return match.group(1) if match else None

# -------------------
# Bucket Access Checkers
# -------------------
def check_s3(bucket):
    if not boto3:
        return False, False
    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")
    readable = writable = False
    try:
        s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
        readable = True
    except ClientError:
        pass
    try:
        test_key = f"misconfig_test_{int(time.time())}.txt"
        s3.put_object(Bucket=bucket, Key=test_key, Body=b"test")
        s3.delete_object(Bucket=bucket, Key=test_key)
        writable = True
    except ClientError:
        pass
    return readable, writable

def check_gcs(bucket):
    if not gcs_storage:
        return False, False
    try:
        client = gcs_storage.Client.create_anonymous_client()
        b = client.bucket(bucket)
        readable = writable = False
        try:
            for _ in client.list_blobs(bucket):
                readable = True
                break
        except Exception:
            pass
        try:
            test_blob = b.blob(f"misconfig_test_{int(time.time())}.txt")
            test_blob.upload_from_string("test")
            writable = True
            test_blob.delete()
        except Exception:
            pass
        return readable, writable
    except Exception:
        return False, False

def check_azure(bucket):
    if not BlobServiceClient:
        return False, False
    try:
        service = BlobServiceClient(account_url=f"https://{bucket}.blob.core.windows.net/", credential=None)
        containers = list(service.list_containers())
        return bool(containers), False
    except Exception:
        return False, False

def check_do(bucket):
    return check_s3(bucket)  # DO Spaces mimic S3 API

def check_oracle(bucket):
    import requests
    try:
        url = f"https://{bucket}.objectstorage.us-ashburn-1.oraclecloud.com/"
        r = requests.get(url, timeout=5)
        return r.status_code in (200, 403, 401), False
    except Exception:
        return False, False

# -------------------
# Search
# -------------------
def serpapi_search(query, num=10):
    params = {"engine": "google", "q": query, "hl": "en", "num": num, "api_key": API_KEY}
    search = GoogleSearch(params)
    results = search.get_dict()
    return [res.get("link") for res in results.get("organic_results", []) if res.get("link")]

# -------------------
# Save results
# -------------------
def save_scan(target, data):
    filename = f"{target}_deep.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"\n[✓] Scan results saved to {filename}")

# -------------------
# Main process
# -------------------
def bucket_scan(domain):
    print(Style.BRIGHT + Fore.LIGHTBLUE_EX + f"\n=== [ Bucket Scan Started for {domain} ] ===")

    result = {
        "bucket": {"timestamp": datetime.now().isoformat(), "domain": domain},
        "target": domain,
        "scan_type": "deep",
        "timestamp": datetime.utcnow().isoformat() + "+00:00"
    }

    # DNS & WHOIS
    ips = get_dns_records(domain)
    result["bucket"]["dns"] = ips
    result["bucket"]["whois"] = [{"ip": ip, "whois": get_whois_info(ip)} for ip in ips]

    # Bucket search queries
    result["bucket"].update({
        "AWS_S3": [], "Google_Cloud": [], "Azure": [], "DigitalOcean": [], "Oracle_Cloud": []
    })

    queries = {
        "AWS_S3": f'site:*.s3.amazonaws.com "{domain}"',
        "Google_Cloud": f'site:*.storage.googleapis.com "{domain}"',
        "Azure": f'site:*.blob.core.windows.net "{domain}"',
        "DigitalOcean": f'site:*.digitaloceanspaces.com "{domain}"',
        "Oracle_Cloud": f'site:objectstorage.*.oraclecloud.com "{domain}"'
    }

    for cloud, query in queries.items():
        print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"\n--- [ {cloud} Enumeration ] ---")
        urls = serpapi_search(query)
        if not urls:
            print(Fore.LIGHTYELLOW_EX + f"[!] No {cloud} buckets found.")
            continue
        for url in urls:
            if cloud == "AWS_S3":
                bucket = extract_s3_bucket(url)
                r, w = check_s3(bucket) if bucket else (False, False)
                entry = {"url": url, "bucket": bucket, "read": r, "write": w}
            elif cloud == "Google_Cloud":
                bucket = extract_gcs_bucket(url)
                r, w = check_gcs(bucket) if bucket else (False, False)
                entry = {"url": url, "bucket": bucket, "read": r, "write": w}
            elif cloud == "Azure":
                bucket = extract_azure_bucket(url)
                r, w = check_azure(bucket) if bucket else (False, False)
                container = urlparse(url).path.strip("/").split("/")[0] if urlparse(url).path else None
                entry = {"url": url, "account": bucket, "container": container, "read": r, "write": w}
            elif cloud == "DigitalOcean":
                bucket = extract_do_bucket(url)
                r, w = check_do(bucket) if bucket else (False, False)
                entry = {"url": url, "bucket": bucket, "read": r, "write": w}
            elif cloud == "Oracle_Cloud":
                bucket = extract_oracle_bucket(url)
                r, w = check_oracle(bucket) if bucket else (False, False)
                entry = {"url": url, "bucket": bucket, "read": r, "write": w}
            else:
                entry = {}

            if entry and entry.get("bucket"):
                result["bucket"][cloud].append(entry)
                color = Fore.LIGHTGREEN_EX if (entry["read"] or entry["write"]) else Fore.LIGHTBLACK_EX
                print(color + f"[+] {cloud} bucket found: {entry}")

    save_scan(domain, result)
    return result

# -------------------
# Entry
# -------------------
def process(domain):
    return bucket_scan(domain)

if __name__ == "__main__":
    target_domain = input(Fore.LIGHTBLUE_EX + "\nEnter target domain: ").strip()
    if not target_domain:
        print(Fore.LIGHTRED_EX + "[!] Domain required. Exiting.")
        exit()
    process(target_domain)
