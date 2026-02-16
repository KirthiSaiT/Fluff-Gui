import json
import os
import sys

def generate_spf(scan_file):
    # Derive target name
    target_name = os.path.basename(scan_file).replace("_lite.json", "")

    # Load input JSON
    with open(scan_file, "r") as f:
        data = json.load(f)

    output = {
        "ips": {},
        "subdomains": [],
        "emails": []
    }

    # Extract IPs, open_ports, CVEs from Shodan results
    for result in data.get("shodanlite", {}).get("shodan_results", []):
        ip = result.get("ip")
        if ip:
            output["ips"][ip] = {
                "open_ports": [str(result.get("port"))] if result.get("port") else [],
                "cves": result.get("vulnerabilities", [])
            }

    # Extract subdomains
    output["subdomains"] = data.get("subdomain", {}).get("alive", [])

    # Extract emails
    output["emails"] = data.get("emailscrap", {}).get("emails", [])

    # Save SPF JSON
    spf_file = f"{target_name}_spf.json"
    with open(spf_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[✓] SPF JSON saved → {spf_file}")


if __name__ == "__main__":
    # Use command line argument or auto-detect
    if len(sys.argv) > 1:
        scan_file = sys.argv[1]
        generate_spf(scan_file)
    else:
        for file in os.listdir("."):
            if file.endswith("_lite.json"):
                generate_spf(file)
