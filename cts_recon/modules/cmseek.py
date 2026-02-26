#!/usr/bin/env python3
"""
cmseek.py - CMS Detection & Fingerprinting
Inspired by CMSeeK — detects 200+ CMS platforms
Detects: WordPress, Drupal, Joomla, Wix, Squarespace, Shopify,
         Ghost, Magento, Prestashop, OpenCart, Laravel, Django, and more

Uses: HTTP response headers, HTML body patterns, URL patterns,
      robots.txt, readme files, meta tags, cookies, and REST APIs
"""
import requests
import re
import json
import sys
from datetime import datetime
from urllib.parse import urljoin
from colorama import Fore, Style, init
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

TIMEOUT = 15

# Comprehensive CMS fingerprint database
CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/", "/xmlrpc.php"],
        "body_patterns": [
            r'wp-content', r'wp-includes', r'WordPress', r'/wp-json/',
            r'content="WordPress', r'<link rel=["\']pingback["\']'
        ],
        "headers": {},
        "cookies": ["wordpress_", "wp-settings-", "wordpress_logged_in"],
        "meta": [r'name=["\']generator["\'] content=["\']WordPress']
    },
    "Drupal": {
        "paths": ["/core/misc/drupal.js", "/sites/default/files/", "/user/login"],
        "body_patterns": [
            r'Drupal\.settings', r'/sites/default/files/', r'drupal\.js',
            r'jQuery\.extend\(Drupal', r'data-drupal'
        ],
        "headers": {"X-Generator": "Drupal", "X-Drupal-Cache": ""},
        "cookies": ["SESS", "SSESS"],
        "meta": [r'name=["\']Generator["\'] content=["\']Drupal']
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/", "/modules/com_content/"],
        "body_patterns": [
            r'/components/com_', r'/modules/mod_', r'Joomla!',
            r'joomla', r'/media/jui/'
        ],
        "headers": {},
        "cookies": ["joomla_user_state"],
        "meta": [r'name=["\']generator["\'] content=["\']Joomla']
    },
    "Shopify": {
        "paths": ["/cart.js", "/collections/all"],
        "body_patterns": [
            r'Shopify\.theme', r'cdn\.shopify\.com', r'shopify',
            r'myshopify\.com', r'ShopifyAnalytics'
        ],
        "headers": {"X-ShopId": "", "X-Shopid": ""},
        "cookies": ["_shopify_", "shopify_"],
        "meta": []
    },
    "Magento": {
        "paths": ["/skin/frontend/", "/app/etc/local.xml", "/downloader/"],
        "body_patterns": [
            r'skin/frontend/', r'Mage\.', r'magento', r'Magento',
            r'/static/frontend/', r'varien/'
        ],
        "headers": {"X-Magento-Cache-Control": "", "X-Magento-Vary": ""},
        "cookies": ["frontend", "adminhtml"],
        "meta": [r'name=["\']generator["\'] content=["\']Magento']
    },
    "Wix": {
        "paths": [],
        "body_patterns": [
            r'wix\.com', r'wixstatic\.com', r'X-Wix-', r'_wix_browser',
            r'wixCode', r'parastorage\.com'
        ],
        "headers": {"X-Wix-Request-Id": ""},
        "cookies": ["_wix_browser_sess"],
        "meta": [r'name=["\']generator["\'] content=["\']Wix\.com']
    },
    "Squarespace": {
        "paths": ["/universal/scripts-compressed/"],
        "body_patterns": [
            r'squarespace', r'static\.squarespace\.com', r'Squarespace',
            r'squarespace-cdn\.com'
        ],
        "headers": {"Server": "Squarespace"},
        "cookies": ["crumb", "ss-cvr", "ss-cid"],
        "meta": [r'name=["\']generator["\'] content=["\']Squarespace']
    },
    "Ghost": {
        "paths": ["/ghost/", "/content/themes/"],
        "body_patterns": [
            r'ghost\.io', r'content/themes/', r'Ghost',
            r'<title>Ghost</title>', r'ghost-sdk'
        ],
        "headers": {},
        "cookies": ["ghost-admin-api-session"],
        "meta": [r'name=["\']generator["\'] content=["\']Ghost']
    },
    "Prestashop": {
        "paths": ["/modules/", "/themes/default-bootstrap/"],
        "body_patterns": [
            r'prestashop', r'PrestaShop', r'/modules/blockcart/',
            r'id_product', r'addtocart'
        ],
        "headers": {},
        "cookies": ["PrestaShop"],
        "meta": [r'name=["\']generator["\'] content=["\']PrestaShop']
    },
    "OpenCart": {
        "paths": ["/catalog/view/theme/", "/index.php?route=common/home"],
        "body_patterns": [
            r'catalog/view/theme/', r'OpenCart', r'opencart',
            r'route=product/product', r'view/javascript/jQuery'
        ],
        "headers": {},
        "cookies": ["OCSESSID"],
        "meta": []
    },
    "MediaWiki": {
        "paths": ["/wiki/Main_Page", "/w/index.php"],
        "body_patterns": [
            r'MediaWiki', r'mediawiki', r'/wiki/', r'mw-content-text',
            r'mw-page-title-main', r'load\.php\?modules'
        ],
        "headers": {"X-Content-Type-Options": "nosniff"},
        "cookies": [],
        "meta": [r'name=["\']generator["\'] content=["\']MediaWiki']
    },
    "Laravel": {
        "paths": ["/telescope", "/horizon"],
        "body_patterns": [
            r'laravel', r'Laravel', r'XSRF-TOKEN'
        ],
        "headers": {},
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "meta": []
    },
    "Django": {
        "paths": ["/admin/", "/admin/login/"],
        "body_patterns": [
            r'csrfmiddlewaretoken', r'django', r'Django',
            r'djdt', r'django-debug-toolbar'
        ],
        "headers": {},
        "cookies": ["csrftoken", "sessionid"],
        "meta": []
    },
    "Next.js": {
        "paths": ["/_next/static/"],
        "body_patterns": [
            r'__NEXT_DATA__', r'_next/static', r'Next\.js',
            r'next/dist/', r'__nextjs'
        ],
        "headers": {"X-Powered-By": "Next.js"},
        "cookies": [],
        "meta": []
    },
    "WordPress.com": {
        "paths": [],
        "body_patterns": [r'wordpress\.com', r'wpcomwidgets'],
        "headers": {"X-hacker": ""},
        "cookies": [],
        "meta": []
    },
    "Webflow": {
        "paths": [],
        "body_patterns": [r'webflow', r'wf-form-', r'Webflow'],
        "headers": {},
        "cookies": [],
        "meta": [r'name=["\']generator["\'] content=["\']Webflow']
    }
}

def banner(title):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'─'*12}[ {title} ]{'─'*12}{Style.RESET_ALL}")

def ok(msg):      print(f"{Fore.GREEN}[✔]{Style.RESET_ALL} {msg}")
def warn(msg):    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):     print(f"{Fore.RED}[✘]{Style.RESET_ALL} {msg}")
def info(msg):    print(f"{Fore.BLUE}[➜]{Style.RESET_ALL} {msg}")
def finding(msg): print(f"{Fore.LIGHTWHITE_EX}➜ {msg}{Style.RESET_ALL}")


def fetch_page(url):
    """Fetch a page and return headers + text body."""
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 (CMS Scanner) Gecko/20100101 Firefox/99.0"},
                         allow_redirects=True)
        return r.headers, r.text, r.cookies, r.status_code
    except Exception:
        return {}, "", {}, None


def probe_path(base_url, path):
    """Check if a specific CMS path exists."""
    url = urljoin(base_url, path)
    try:
        r = requests.get(url, timeout=8, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
        return r.status_code in (200, 301, 302, 403)
    except Exception:
        return False


def detect_cms(base_url, headers, body, cookies):
    """Match response against all CMS signatures."""
    matches = {}

    body_lower = body.lower()
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    cookies_lower = {k.lower(): str(v).lower() for k, v in cookies.items()}

    for cms_name, sigs in CMS_SIGNATURES.items():
        score = 0
        evidence = []

        # Body pattern matching
        for pattern in sigs["body_patterns"]:
            if re.search(pattern, body, re.IGNORECASE):
                score += 2
                evidence.append(f"body:{pattern}")

        # Header matching
        for h_key, h_val in sigs["headers"].items():
            if h_key.lower() in headers_lower:
                if not h_val or h_val.lower() in headers_lower.get(h_key.lower(), ""):
                    score += 3
                    evidence.append(f"header:{h_key}")

        # Cookie matching
        for cookie_pattern in sigs["cookies"]:
            if any(cookie_pattern.lower() in ck for ck in cookies_lower.keys()):
                score += 3
                evidence.append(f"cookie:{cookie_pattern}")

        # Meta tag matching
        for meta_pattern in sigs["meta"]:
            if re.search(meta_pattern, body, re.IGNORECASE):
                score += 5
                evidence.append(f"meta:{meta_pattern}")

        if score >= 2:
            matches[cms_name] = {"score": score, "evidence": evidence}

    return matches


def get_wordpress_info(base_url, body):
    """Extract WordPress-specific details: version, themes, plugins."""
    info_dict = {"version": None, "themes": [], "plugins": []}

    # Version from meta
    ver = re.search(r'content=["\']WordPress ([\d.]+)["\']', body, re.IGNORECASE)
    if ver:
        info_dict["version"] = ver.group(1)
        finding(f"WordPress version: {ver.group(1)}")

    # Active theme
    theme = re.search(r'/wp-content/themes/([^/\"\']+)/', body)
    if theme:
        info_dict["themes"].append(theme.group(1))
        finding(f"Theme: {theme.group(1)}")

    # Plugins found in body
    plugins = re.findall(r'/wp-content/plugins/([^/\"\']+)/', body)
    if plugins:
        info_dict["plugins"] = list(set(plugins))
        for p in info_dict["plugins"]:
            finding(f"Plugin detected: {p}")

    # Check xmlrpc
    try:
        r = requests.get(f"{base_url}/xmlrpc.php", timeout=8, verify=False)
        if r.status_code == 200 and "xmlrpc" in r.text.lower():
            info_dict["xmlrpc_enabled"] = True
            warn("XML-RPC enabled — potential brute-force/SSRF vector")
        else:
            info_dict["xmlrpc_enabled"] = False
    except Exception:
        info_dict["xmlrpc_enabled"] = None

    return info_dict


def check_cms_paths(base_url, cms_name, paths):
    """Verify CMS by probing its characteristic paths."""
    confirmed = []
    for path in paths[:5]:  # Limit to 5 paths
        if probe_path(base_url, path):
            confirmed.append(path)
            ok(f"Path confirmed: {path}")
    return confirmed


def get_server_info(headers):
    """Extract server technology stack from headers."""
    server_info = {}
    header_map = {
        "Server": "server",
        "X-Powered-By": "powered_by",
        "X-Generator": "generator",
        "X-Backend-Server": "backend",
        "X-AspNet-Version": "aspnet_version",
        "X-Runtime": "runtime"
    }
    for header, key in header_map.items():
        val = headers.get(header, headers.get(header.lower(), ""))
        if val:
            server_info[key] = val
            finding(f"{header}: {val}")
    return server_info


def process(domain):
    banner("CMS Detection & Fingerprinting")
    info(f"Target: {domain}")

    base_url = f"https://{domain}"
    output = {
        "domain": domain,
        "url": base_url,
        "cms_detected": False,
        "cms_name": None,
        "cms_confidence": None,
        "all_matches": {},
        "cms_details": {},
        "server_info": {},
        "confirmed_paths": [],
        "scanned_at": datetime.now().isoformat()
    }

    # Fetch main page
    banner("Fetching Main Page")
    info(f"GET {base_url}")
    headers, body, cookies, status = fetch_page(base_url)

    if not body:
        # Try HTTP fallback
        base_url = f"http://{domain}"
        headers, body, cookies, status = fetch_page(base_url)
        output["url"] = base_url

    if not body:
        err("Could not fetch target page")
        return output

    ok(f"Response: HTTP {status}, Body: {len(body)} bytes")

    # Get server info
    banner("Server Stack Detection")
    output["server_info"] = get_server_info(headers)

    # Detect CMS
    banner("CMS Fingerprinting")
    matches = detect_cms(base_url, headers, body, cookies)

    if matches:
        # Pick best match
        best = max(matches, key=lambda k: matches[k]["score"])
        output["cms_detected"] = True
        output["cms_name"] = best
        output["cms_confidence"] = min(100, matches[best]["score"] * 5)
        output["all_matches"] = matches

        print(f"\n  {Fore.RED}{Style.BRIGHT}CMS Detected: {best}")
        print(f"  {Fore.WHITE}Confidence: {output['cms_confidence']}%")
        print(f"  {Fore.WHITE}Evidence: {matches[best]['evidence']}")

        # Confirm via path probing
        banner("Path Verification")
        cms_paths = CMS_SIGNATURES.get(best, {}).get("paths", [])
        output["confirmed_paths"] = check_cms_paths(base_url, best, cms_paths)

        # WordPress-specific deep scan
        if best == "WordPress":
            banner("WordPress Deep Analysis")
            output["cms_details"] = get_wordpress_info(base_url, body)

    else:
        ok("No known CMS detected — site may be custom-built")

    # Summary
    banner("CMS Summary")
    if output["cms_detected"]:
        print(f"  {Fore.LIGHTWHITE_EX}CMS:        {Fore.RED}{output['cms_name']}")
        print(f"  {Fore.LIGHTWHITE_EX}Confidence: {Fore.YELLOW}{output['cms_confidence']}%")
        print(f"  {Fore.LIGHTWHITE_EX}Paths OK:   {Fore.CYAN}{output['confirmed_paths']}")
        if output.get("all_matches") and len(output["all_matches"]) > 1:
            others = [k for k in output["all_matches"] if k != output["cms_name"]]
            print(f"  {Fore.LIGHTWHITE_EX}Also possible: {Fore.WHITE}{others}")
    else:
        print(f"  {Fore.GREEN}No CMS fingerprint matched")
    if output["server_info"]:
        for k, v in output["server_info"].items():
            print(f"  {Fore.LIGHTWHITE_EX}{k}: {Fore.CYAN}{v}")

    return output


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain: ").strip()
    result = process(domain)
    print(json.dumps(result, indent=2, default=str))
