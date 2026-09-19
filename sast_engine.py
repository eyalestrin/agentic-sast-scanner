#!/usr/bin/env python3
"""
Agentic SAST Engine
-------------------
Handles directory traversal, 400-line chunking, state checkpointing,
built-in heuristic fallback scanning across High/Medium/Low severities,
schema validation, OWASP Cheat Sheet mapping, and multi-format 
(HTML, SARIF, JSON, Markdown, PDF) report generation.
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path

# PDF Generation Dependencies
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

SUPPORTED_EXTENSIONS = {
    '.py': 'Python', '.java': 'Java', '.cs': '.NET/C#', '.js': 'JavaScript',
    '.ts': 'TypeScript', '.pl': 'Perl', '.pm': 'Perl', '.php': 'PHP',
    '.c': 'C', '.cpp': 'C++', '.go': 'Go', '.rb': 'Ruby', '.rs': 'Rust'
}

EXCLUDED_DIRS = {'.git', 'node_modules', 'venv', '.venv', 'target', 'bin', 'obj', '__pycache__'}
CHECKPOINT_FILE = "sast_checkpoint.json"

# Static heuristic fallback rules for command-line runs
STATIC_HEURISTIC_RULES = [
    # Critical / High Severity Rules
    {
        "title": "OS Command Injection via Runtime / Shell Execution",
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "pattern": r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|os\.system|subprocess\.Popen|exec\s*\(.*sh)",
        "remediation": "Avoid invoking system shells directly. Parameterize arguments using structured array APIs.",
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Command_Injection_Defense_Cheat_Sheet.html"
        ]
    },
    {
        "title": "Potential SQL Injection via String Concatenation",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "severity": "HIGH",
        "pattern": r"(SELECT|INSERT|UPDATE|DELETE).*\+.*",
        "remediation": "Use parameterized prepared statements instead of dynamic SQL string concatenation.",
        "references": [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"
        ]
    },
    {
        "title": "Potential Server-Side Request Forgery (SSRF)",
        "cwe_id": "CWE-918",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
        "severity": "HIGH",
        "pattern": r"(\.exchange\(|\.getForObject\(|requests\.get\(|fetch\().*request\.",
        "remediation": "Validate target URLs against an explicit allowlist and block access to private/internal network ranges.",
        "references": [
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
        ]
    },
    {
        "title": "Path Traversal / Unsanitized File Access",
        "cwe_id": "CWE-22",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity": "HIGH",
        "pattern": r"(FileReader|FileInputStream|open\().*path",
        "remediation": "Canonicalize file paths using Path.toRealPath() before enforcing access boundaries.",
        "references": [
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Path_Traversal_Cheat_Sheet.html"
        ]
    },
    # Medium / Low Severity Rules
    {
        "title": "Sensitive Information Logging / Verbose Output",
        "cwe_id": "CWE-532",
        "owasp_category": "A09:2021-Security Logging and Monitoring Failures",
        "severity": "MEDIUM",
        "pattern": r"(log\.info|log\.debug|System\.out\.println)\(.*(password|secret|key|path|domainName|url)",
        "remediation": "Sanitize and mask sensitive variables before writing them to application log output.",
        "references": [
            "https://cwe.mitre.org/data/definitions/532.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
        ]
    },
    {
        "title": "Disabled CSRF Protection",
        "cwe_id": "CWE-352",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity": "MEDIUM",
        "pattern": r"\.csrf\(\)\.disable\(\)",
        "remediation": "Re-enable CSRF protection for state-changing HTTP endpoints.",
        "references": [
            "https://cwe.mitre.org/data/definitions/352.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
        ]
    },
    {
        "title": "Generic Exception Catching / Potential Stack Trace Exposure",
        "cwe_id": "CWE-396",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "severity": "LOW",
        "pattern": r"catch\s*\(\s*Exception\s+e\s*\)",
        "remediation": "Catch specific exception types rather than generic Exception to avoid swallowing critical errors or exposing stack traces.",
        "references": [
            "https://cwe.mitre.org/data/definitions/396.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
        ]
    }
]

def analyze_line_heuristics(line, line_num, file_path):
    """Evaluates a single line of code against built-in static patterns."""
    findings = []
    for rule in STATIC_HEURISTIC_RULES:
        if re.search(rule["pattern"], line, re.IGNORECASE):
            findings.append({
                "title": rule["title"],
                "cwe_id": rule["cwe_id"],
                "owasp_category": rule["owasp_category"],
                "severity": rule["severity"],
                "file_path": file_path,
                "start_line": line_num,
                "end_line": line_num,
                "vulnerable_code": line.strip(),
                "remediation": rule["remediation"],
                "references": rule["references"]
            })
    return findings

def load_or_scan_checkpoint(target_dir):
    """Loads valid vulnerability findings from sast_checkpoint.json or runs fallback scan."""
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                raw_findings = []
                if isinstance(data, list):
                    raw_findings = data
                elif isinstance(data, dict) and "findings" in data:
                    raw_findings = data["findings"]
                
                # Filter to ensure items are actual security findings, not raw file chunk metadata
                valid_findings = [
                    item for item in raw_findings 
                    if isinstance(item, dict) and ("title" in item or "cwe_id" in item or "vulnerable_code" in item)
                ]

                if valid_findings:
                    return valid_findings
                else:
                    print("[-] Found checkpoint file, but it contains raw chunk metadata instead of vulnerability findings. Running fallback scan...")
        except Exception as e:
            print(f"[-] Warning: Failed to parse existing {CHECKPOINT_FILE}: {e}")

    print("[+] Executing static heuristic analysis across source files...")
    findings = []
    chunks_count = 0

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for file in files:
            ext = Path(file).suffix.lower()
            if ext in SUPPORTED_EXTENSIONS:
                full_path = Path(root) / file
                rel_path = str(full_path.relative_to(target_dir))
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    chunks_count += (len(lines) // 400) + 1
                    for line_idx, line in enumerate(lines, start=1):
                        matched = analyze_line_heuristics(line, line_idx, rel_path)
                        findings.extend(matched)
                except Exception as e:
                    print(f"[-] Error processing {rel_path}: {e}")

    # Persist verified findings checkpoint
    with open(CHECKPOINT_FILE, 'w', encoding='utf-8') as f:
        json.dump({"chunks": chunks_count, "findings": findings}, f, indent=2)

    return findings

def generate_pdf_report(findings, output_pdf_path="sast_security_report.pdf"):
    """Generates mandatory PDF security report using ReportLab."""
    doc = SimpleDocTemplate(output_pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=12
    )

    story.append(Paragraph("Static Application Security Testing (SAST) Audit Report", title_style))
    story.append(Paragraph(f"<b>Total Vulnerabilities Identified:</b> {len(findings)}", styles['Normal']))
    story.append(Spacer(1, 16))

    if not findings:
        story.append(Paragraph("No security vulnerabilities detected across project code chunks.", styles['Normal']))
    else:
        for index, item in enumerate(findings, start=1):
            sev = item.get('severity', 'MEDIUM').upper()
            if sev in ['CRITICAL', 'HIGH']:
                sev_color = "#dc2626"
            elif sev == 'MEDIUM':
                sev_color = "#d97706"
            else:
                sev_color = "#2563eb"

            header_text = f"<b>{index}. {item.get('title', 'Security Finding')}</b> - <font color='{sev_color}'><b>{sev}</b></font>"
            story.append(Paragraph(header_text, styles['Heading2']))

            details = [
                [Paragraph("<b>CWE / Taxonomy:</b>", styles['Normal']), Paragraph(f"{item.get('cwe_id', 'N/A')} ({item.get('owasp_category', 'N/A')})", styles['Normal'])],
                [Paragraph("<b>File Location:</b>", styles['Normal']), Paragraph(f"{item.get('file_path')} (Line {item.get('start_line')})", styles['Normal'])],
            ]

            t = Table(details, colWidths=[130, 370])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(t)
            story.append(Spacer(1, 8))

            story.append(Paragraph("<b>Vulnerable Code Snippet:</b>", styles['Normal']))
            story.append(Preformatted(item.get('vulnerable_code', 'N/A'), styles['Code']))
            story.append(Spacer(1, 6))

            story.append(Paragraph(f"<b>Remediation Strategy:</b> {item.get('remediation', 'N/A')}", styles['Normal']))

            if item.get('references'):
                refs = "<br/>".join([f"<a href='{r}'>{r}</a>" for r in item.get('references')])
                story.append(Paragraph(f"<b>References:</b><br/>{refs}", styles['Normal']))

            story.append(Spacer(1, 14))

    doc.build(story)
    print(f"[+] Mandatory PDF report generated: {output_pdf_path}")

def generate_html_report(findings, output_html_path="sast_report.html"):
    """Generates user-selected HTML report."""
    rows = ""
    for item in findings:
        sev = item.get('severity', 'MEDIUM').upper()
        if sev == "CRITICAL":
            badge_class = "critical"
        elif sev == "HIGH":
            badge_class = "high"
        elif sev == "MEDIUM":
            badge_class = "medium"
        else:
            badge_class = "low"

        refs_html = ""
        if item.get('references'):
            refs_html = "<br/><small>" + "<br/>".join([f"<a href='{r}' target='_blank'>{r}</a>" for r in item.get('references')]) + "</small>"

        rows += f"""
        <tr>
            <td><span class="badge {badge_class}">{sev}</span></td>
            <td><b>{item.get('title')}</b><br/><small>{item.get('cwe_id')} | {item.get('owasp_category')}</small></td>
            <td><code>{item.get('file_path')}:{item.get('start_line')}</code></td>
            <td><pre><code>{item.get('vulnerable_code')}</code></pre></td>
            <td>{item.get('remediation')}{refs_html}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>SAST Security Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background: #f8fafc; color: #0f172a; }}
        h1 {{ color: #0f172a; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
        th {{ background: #f1f5f9; }}
        pre {{ background: #0f172a; color: #f8fafc; padding: 8px; border-radius: 4px; overflow-x: auto; font-size: 12px; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; color: white; }}
        .critical {{ background: #dc2626; }}
        .high {{ background: #ea580c; }}
        .medium {{ background: #d97706; }}
        .low {{ background: #2563eb; }}
    </style>
</head>
<body>
    <h1>Static Application Security Testing (SAST) Report</h1>
    <p><b>Total Findings:</b> {len(findings)}</p>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Vulnerability & Taxonomy</th>
                <th>Location</th>
                <th>Code Snippet</th>
                <th>Remediation & OWASP References</th>
            </tr>
        </thead>
        <tbody>
            {rows if rows else "<tr><td colspan='5'>No vulnerabilities identified.</td></tr>"}
        </tbody>
    </table>
</body>
</html>"""

    with open(output_html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"[+] HTML report generated: {output_html_path}")

def generate_sarif_report(findings, output_sarif_path="sast_report.sarif"):
    """Generates SARIF format report for IDE and CI/CD ingestion."""
    sarif_rules = []
    sarif_results = []

    for index, item in enumerate(findings):
        rule_id = f"SAST-{item.get('cwe_id', 'UNKNOWN')}-{index}"
        sarif_rules.append({
            "id": rule_id,
            "name": item.get('title'),
            "shortDescription": {"text": item.get('title')},
            "fullDescription": {"text": item.get('remediation')},
            "help": {"text": f"Remediation: {item.get('remediation')}"}
        })
        sarif_results.append({
            "ruleId": rule_id,
            "message": {"text": f"{item.get('title')}: {item.get('remediation')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": item.get('file_path')},
                    "region": {"startLine": item.get('start_line', 1)}
                }
            }]
        })

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Agentic SAST Scanner",
                    "informationUri": "https://github.com/eyalestrin/agentic-sast-scanner",
                    "rules": sarif_rules
                }
            },
            "results": sarif_results
        }]
    }

    with open(output_sarif_path, 'w', encoding='utf-8') as f:
        json.dump(sarif_data, f, indent=2)
    print(f"[+] SARIF report generated: {output_sarif_path}")

def main():
    parser = argparse.ArgumentParser(description="Cross-Platform Agentic SAST Engine")
    parser.add_argument("--format", choices=["markdown", "sarif", "json", "html"], default="html")
    parser.add_argument("--dir", default=".")
    args = parser.parse_args()

    target_dir = os.path.abspath(args.dir)
    print(f"[+] Initializing SAST Engine on target folder: {target_dir}")

    findings = load_or_scan_checkpoint(target_dir)
    print(f"[+] Active vulnerability findings loaded: {len(findings)}")

    # Render primary requested report format
    if args.format == "html":
        generate_html_report(findings, "sast_report.html")
    elif args.format == "sarif":
        generate_sarif_report(findings, "sast_report.sarif")
    elif args.format == "json":
        with open("sast_report.json", 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2)
        print("[+] Primary JSON report generated: sast_report.json")
    else:
        out_name = f"sast_report.{'md' if args.format == 'markdown' else args.format}"
        with open(out_name, 'w', encoding='utf-8') as f:
            f.write(f"# SAST Audit Summary\nTotal Findings: {len(findings)}\n\n")
            for item in findings:
                f.write(f"## {item.get('title')} ({item.get('severity')})\n")
                f.write(f"- Location: `{item.get('file_path')}:{item.get('start_line')}`\n")
                f.write(f"- CWE: {item.get('cwe_id')}\n\n")
        print(f"[+] Primary report generated: {out_name}")

    # Render mandatory PDF report
    generate_pdf_report(findings, "sast_security_report.pdf")

if __name__ == "__main__":
    main()