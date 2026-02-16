#!/usr/bin/env python3
"""
buddy.py - Template-driven Red Team Recon Report Generator

Updates:
- Force PDF filename → {target}_deep_report.pdf
- Force layer filename → {target}_Deep.layer.json
- Fixed __name__ == "__main__" typo
- Always reads {target}_deep.json from the project folder
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER

# -----------------------------
# CONFIG / Mapping
# -----------------------------
CORP_BLUE = colors.HexColor("#0B5394")

KNOWN_MAPPING = {
    "timestamp": ("T1082", "discovery"),
    "domain": ("T1590", "reconnaissance"),
    "dns": ("T1590.001", "reconnaissance"),
    "ip": ("T1590.005", "reconnaissance"),
    "whois": ("T1596.001", "reconnaissance"),
    "Sbucket": ("T1596.005", "reconnaissance"),
    "subdomains": ("T1590.002", "reconnaissance"),
    "alive": ("T1046", "reconnaissance"),
    "tech_scans": ("T1592.002", "reconnaissance"),
    "software": ("T1592.002", "reconnaissance"),
    "emails": ("T1589.002", "reconnaissance"),
    "usernames": ("T1589.003", "reconnaissance"),
    "employee_name": ("T1589.003", "reconnaissance"),
    "phones": ("T1589.001", "reconnaissance"),
    "credentials": ("T1552", "credential-access"),
    "passwords": ("T1552.001", "credential-access"),
    "emailsecurity": ("T1598", "reconnaissance"),
    "spf": ("T1598.002", "reconnaissance"),
    "dmarc": ("T1598.002", "reconnaissance"),
    "dkim": ("T1598.002", "reconnaissance"),
    "social_links": ("T1593.001", "reconnaissance"),
    "social_media": ("T1593.001", "reconnaissance"),
    "broken_links": ("T1593.001", "reconnaissance"),
    "link": ("T1593", "reconnaissance"),
    "clickjacking": ("T1190", "initial-access"),
    "url": ("T1071", "command-and-control"),
    "google_dorks": ("T1592", "reconnaissance"),
    "password_dork": ("T1552.001", "credential-access"),
    "confidential_dork": ("T1590", "reconnaissance"),
    "uncommon_ext_dork": ("T1592", "reconnaissance"),
    "xml_urls": ("T1119", "collection"),
    "json_urls": ("T1213.003", "collection"),
    "pdf_urls": ("T1608.001", "resource-development"),
    "doc_urls": ("T1074.001", "collection"),
    "docx_urls": ("T1074.002", "collection"),
    "txt_urls": ("T1005", "collection"),
    "php_urls": ("T1505.003", "persistence"),
    "shodan": ("T1595", "reconnaissance"),
    "shodan_nmap": ("T1595.001", "reconnaissance"),
    "vulnerability_scanning": ("T1595.002", "reconnaissance"),
    "search_engine": ("T1593.003", "reconnaissance"),
    "search_results": ("T1593.003", "reconnaissance"),
    "vulnerable_urls": ("T1595", "reconnaissance"),
    "gau_urls": ("T1595", "reconnaissance"),
}

MITRE_TECHNIQUE_NAMES = {
    "T1082": "System Information Discovery",
    "T1590": "Gather Victim Network Information",
    "T1590.001": "DNS/Domain Discovery",
    "T1590.002": "Subdomain Discovery",
    "T1590.005": "IP Address Discovery",
    "T1596.001": "WHOIS/Registration Data",
    "T1046": "Network Service Discovery",
    "T1592.002": "Software/Tech Fingerprinting",
    "T1589.002": "Email Addresses",
    "T1589.003": "Usernames",
    "T1589.001": "Phone Numbers",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials in Files",
    "T1598": "Email Security",
    "T1190": "Exploit Public-Facing Application",
    "T1071": "Application Layer Protocol",
    "T1119": "Automated Collection",
    "T1213.003": "APIs / Data Repositories",
    "T1608.001": "PDF/Docs Resources",
    "T1074.001": "Document Collection",
    "T1074.002": "Cloud Staging (docx)",
    "T1005": "Data from Local System (txt)",
    "T1505.003": "Web Shell / PHP persistence",
    "T1595": "Active Scanning",
    "T1595.001": "Nmap/Shodan scanning",
    "T1595.002": "Vulnerability Scanning",
    "T1593.003": "Search Engine Discovery",
}

# -----------------------------
# Helpers
# -----------------------------
def find_deep_json(folder: Path) -> Path:
    files = sorted(folder.glob("*_deep.json"))
    if files:
        return files[0]
    raise FileNotFoundError(f"No deep JSON file found in {folder}. Expected *_deep.json")

def scan_json_collect_keys(obj: Any, found_keys: set):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in KNOWN_MAPPING and v:
                found_keys.add(k)
            scan_json_collect_keys(v, found_keys)
    elif isinstance(obj, list):
        for i in obj:
            scan_json_collect_keys(i, found_keys)

def convert_to_mitre_layer(osint_data: Dict[str, Any], input_file: Path) -> Dict[str, Any]:
    found = set()
    scan_json_collect_keys(osint_data, found)
    techniques = []
    seen = set()
    for k in sorted(found):
        tech_id, tactic = KNOWN_MAPPING.get(k, ("", ""))
        if not tech_id or (tech_id, tactic) in seen:
            continue
        seen.add((tech_id, tactic))
        techniques.append({
            "techniqueID": tech_id,
            "tactic": tactic,
            "comment": k
        })
    return {
        "name": f"{input_file.stem}.layer",
        "version": "4.5",
        "versions": {"attack": "17", "navigator": "4.5"},
        "domain": "enterprise-attack",
        "description": "Automatically generated MITRE mapping from OSINT JSON.",
        "techniques": techniques
    }

# -----------------------------
# Template sections
# -----------------------------
def generate_template_sections(osint_data: Dict[str, Any], layer_data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": "Red Team Reconnaissance Report",
        "executive_summary": "This report provides a high-level summary of reconnaissance findings.",
        "methodology": "Data was collected using automated reconnaissance modules and mapped to MITRE ATT&CK techniques.",
        "risk_assessment": [
            {"severity": "High", "description": "Exposed credentials or misconfigurations were identified."},
            {"severity": "Medium", "description": "Publicly accessible information may increase attack surface."},
            {"severity": "Low", "description": "General OSINT artifacts discovered."},
        ],
        "total_techniques": len(layer_data.get("techniques", [])),
        "tactic_counts": {t["tactic"]: sum(1 for x in layer_data["techniques"] if x["tactic"] == t["tactic"]) for t in layer_data.get("techniques", [])},
        "next_steps": "Further validation and manual penetration testing are recommended.",
        "conclusion": "This reconnaissance provides visibility into the target's exposure landscape.",
    }

# -----------------------------
# PDF generation
# -----------------------------
def generate_pdf_report(input_file: Path, osint_data: Dict[str, Any], layer_data: Dict[str, Any]):
    target_name = input_file.stem.replace("_deep", "")
    output_pdf = input_file.with_name(f"{target_name}_deep_report.pdf")

    doc = SimpleDocTemplate(str(output_pdf), pagesize=letter,
                            rightMargin=40, leftMargin=40,
                            topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Center", alignment=TA_CENTER, fontSize=14, spaceAfter=12))
    story = []

    sections = generate_template_sections(osint_data, layer_data)

    # Title
    story.append(Paragraph(sections["title"], styles["Title"]))
    story.append(Spacer(1, 12))

    # Executive Summary
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(sections["executive_summary"], styles["BodyText"]))
    story.append(Spacer(1, 12))

    # Methodology
    story.append(Paragraph("Methodology", styles["Heading2"]))
    for line in sections["methodology"].split("\n"):
        story.append(Paragraph(line, styles["BodyText"]))
    story.append(Spacer(1, 12))

    # Risk Assessment
    story.append(Paragraph("Risk Assessment", styles["Heading2"]))
    for item in sections["risk_assessment"]:
        story.append(Paragraph(f"<b>{item['severity']}:</b> {item['description']}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    # MITRE Summary
    story.append(Paragraph("MITRE ATT&CK Summary", styles["Heading2"]))
    story.append(Paragraph(f"Total Techniques: {sections['total_techniques']}", styles["BodyText"]))
    for tac, count in sections["tactic_counts"].items():
        story.append(Paragraph(f"{tac.capitalize()}: {count}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    # MITRE Mapping
    story.append(Paragraph("MITRE ATT&CK Mapping", styles["Heading2"]))
    data = [["Artifact", "Tactic", "Technique ID", "Technique Name"]]
    for tech in layer_data.get("techniques", []):
        tech_name = MITRE_TECHNIQUE_NAMES.get(tech["techniqueID"], "Unknown")
        data.append([
            Paragraph(tech["comment"], styles["BodyText"]),
            Paragraph(tech["tactic"], styles["BodyText"]),
            Paragraph(tech["techniqueID"], styles["BodyText"]),
            Paragraph(tech_name, styles["BodyText"])
        ])
    table = Table(data, colWidths=[100, 100, 100, 200], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), CORP_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 12),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))

    # Next Steps
    story.append(Paragraph("Next Steps", styles["Heading2"]))
    for line in sections["next_steps"].split("\n"):
        story.append(Paragraph(line, styles["BodyText"]))
    story.append(Spacer(1, 12))

    # Conclusion
    story.append(Paragraph("Conclusion", styles["Heading2"]))
    story.append(Paragraph(sections["conclusion"], styles["BodyText"]))
    story.append(Spacer(1, 12))

    doc.build(story)
    print(f"PDF report generated: {output_pdf}")

# -----------------------------
# Main
# -----------------------------
def main():
    folder = Path(".")  # always read from project root
    try:
        input_file = find_deep_json(folder)
        print(f"Found deep JSON file: {input_file}")
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)

    with open(input_file, "r", encoding="utf-8") as f:
        osint_data = json.load(f)

    layer_data = convert_to_mitre_layer(osint_data, input_file)

    # Save layer file
    target_name = input_file.stem.replace("_deep", "")
    layer_file = input_file.with_name(f"{target_name}_Deep.layer.json")
    with open(layer_file, "w", encoding="utf-8") as f:
        json.dump(layer_data, f, indent=2)
    print(f"MITRE Navigator layer saved as: {layer_file}")

    # PDF report
    generate_pdf_report(input_file, osint_data, layer_data)

if __name__ == "__main__":
    main()
