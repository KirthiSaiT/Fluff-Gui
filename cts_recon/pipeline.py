#!/usr/bin/env python3
import socket
import subprocess
import importlib
import os
import sys
import json
import webbrowser
from datetime import datetime, timezone
from colorama import Fore, Style, init

# -------- Initialize Colorama --------
init(autoreset=True)

# -------- Global scan collector --------
scan_data = {}

# -------- Paths --------
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
FLASK_DIR = os.path.join(PROJECT_ROOT, "recon_flask")
FLASK_OUTPUT_DIR = os.path.join(FLASK_DIR, "backend", "output")  # flask output
APP_DIR = FLASK_DIR

os.makedirs(FLASK_OUTPUT_DIR, exist_ok=True)


# -------- CLI Helpers --------
def status(msg):
    print(Fore.LIGHTCYAN_EX + "[*] " + Style.RESET_ALL + msg)


def success(msg):
    print(Fore.LIGHTGREEN_EX + "[+] " + Style.RESET_ALL + msg)


def warning(msg):
    print(Fore.LIGHTYELLOW_EX + "[!] " + Style.RESET_ALL + msg)


def error(msg):
    print(Fore.LIGHTRED_EX + "[-] " + Style.RESET_ALL + msg)


# -------- Classify Input --------
def classify_input(input_string):
    """Check if input is IP or Domain"""
    try:
        socket.inet_aton(input_string)
        return "IP"
    except socket.error:
        return "DOMAIN"


# -------- Convert IP to Domain --------
def ip_to_domain(ip):
    """Convert IP to domain using nslookup"""
    try:
        status(f"Resolving IP {ip} to domain...")
        result = subprocess.run(["nslookup", ip], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "name =" in line:
                domain = line.split(" = ")[1].strip()
                success(f"Resolved to {domain}")
                return domain
        warning("No domain found for this IP.")
        return None
    except Exception as e:
        error(f"nslookup error: {e}")
        return None


# -------- Save Master Scan File --------
def save_scan_file(domain, scan_type):
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    filename = f"{safe_domain}_lite.json" if scan_type == "lite" else f"{safe_domain}_deep.json"

    # Add metadata
    scan_data["target"] = domain
    scan_data["scan_type"] = scan_type
    scan_data["timestamp"] = datetime.now(timezone.utc).isoformat()

    try:
        # --- Save in project root ---
        project_path = os.path.join(PROJECT_ROOT, filename)
        with open(project_path, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=4)
        success(f"Scan data saved → {project_path}")

        # --- Save in Flask output ---
        flask_path = os.path.join(FLASK_OUTPUT_DIR, filename)
        with open(flask_path, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=4)
        success(f"Scan data copied → {flask_path}")

    except Exception as e:
        error(f"Failed to save scan file: {e}")
        return None

    return project_path


# -------- Dynamic Module Loader --------
def route_to_modules(domain, modules_dir):
    if not os.path.isdir(modules_dir):
        error(f"Modules directory not found: {modules_dir}")
        return

    for file in sorted(os.listdir(modules_dir)):
        if file.endswith(".py") and not file.startswith("__"):
            module_basename = file[:-3]
            module_name = f"{os.path.basename(modules_dir)}.{module_basename}"

            try:
                module = importlib.import_module(module_name)
                importlib.reload(module)

                if hasattr(module, "process"):
                    status(f"Running {module_name}...")
                    result = module.process(domain)
                    scan_data[module_basename] = result
                    success(f"{module_name} completed")
                else:
                    warning(f"{module_name} has no process(domain) function.")
            except Exception as e:
                error(f"{module_basename} failed: {e}")


# -------- Launch Flask App --------
def launch_flask():
    status("Starting Flask app...")
    try:
        subprocess.Popen([sys.executable, "app.py"], cwd=APP_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        success("Flask app running at http://127.0.0.1:8000")
        # webbrowser.open("http://127.0.0.1:8000")
    except Exception as e:
        error(f"Failed to start Flask app: {e}")


# -------- Run SpiderFoot then Launch Flask (for lite scan) --------
def run_spiderfoot_and_launch(domain):
    try:
        # Check if spiderfoot is available
        import shutil
        if not shutil.which("spiderfoot"):
            status("SpiderFoot not found. Skipping...")
            return

        spider_cmd = (
            "start /B spiderfoot -l 127.0.0.1:5001 && "
            "python -c \"import time; time.sleep(5)\" && "
            f"spiderfoot -s {domain} -m sfp_jsonimport"
        )

        process = subprocess.Popen(
            spider_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )

        for line in iter(process.stdout.readline, ""):
            print(line, end="")
            if "✅ JSON Import completed successfully." in line:
                success("Detected JSON import completion. Launching Flask app now.")
                launch_flask()

        process.stdout.close()
        process.wait()

        success(f"SpiderFoot JSON import scan triggered for {domain}")
    except Exception as e:
        error(f"SpiderFoot failed: {e}")


# -------- Run Report.py (for lite) --------
def run_report(json_file):
    try:
        status(f"Generating report from {json_file} using report.py...")
        subprocess.run([sys.executable, "report.py", json_file], check=True)
        success("Report generation completed.")
    except Exception as e:
        error(f"report.py failed: {e}")


# -------- Run Buddy.py (for deep) --------
def run_buddy(json_file):
    try:
        status(f"Generating PDF report from {json_file} using buddy.py...")
        subprocess.run([sys.executable, "buddy.py", json_file], check=True)
        success("Buddy.py report generation completed.")
    except Exception as e:
        error(f"buddy.py failed: {e}")


# -------- Main Pipeline --------
def pipeline(input_string, scan_type="deep"):
    global scan_data
    scan_data = {}  # reset per run

    input_type = classify_input(input_string)
    status(f"Input classified as: {input_type}")

    if input_type == "IP":
        domain = ip_to_domain(input_string)
        if not domain:
            error("Exiting.")
            return
    else:
        domain = input_string

    print("\nTarget:", Fore.LIGHTGREEN_EX + domain + Style.RESET_ALL)
    print("Scan Type:", Fore.LIGHTYELLOW_EX + scan_type.upper() + Style.RESET_ALL)
    print("-" * 50)

    # --- Run modules ---
    modules_dir = os.path.join(PROJECT_ROOT, "litemodules" if scan_type == "lite" else "modules")
    route_to_modules(domain, modules_dir)

    # --- Save results ---
    filepath = save_scan_file(domain, scan_type)

    # Lite scan → Report.py → SpiderFoot → Flask
    if scan_type == "lite":
        if filepath:
            run_report(filepath)
        run_spiderfoot_and_launch(domain)
    else:
        # Deep scan → Buddy.py → Flask
        if filepath:
            run_buddy(filepath)
        launch_flask()

    return filepath


# -------- Entry Point --------
if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            user_input = sys.argv[1]
        else:
            user_input = input("Enter domain or IP: ").strip()

        print("\nSelect Scan Type:")
        print("  1) Lite Scan  (fast)")
        print("  2) Deep Scan  (detailed)")
        choice = input("Choice (1/2): ").strip()

        scan_type = "lite" if choice == "1" else "deep"
        pipeline(user_input, scan_type)

    except KeyboardInterrupt:
        print(Fore.LIGHTYELLOW_EX + "\n[!] Manually aborted by user" + Style.RESET_ALL)
        sys.exit(0)
