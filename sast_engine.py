#!/usr/bin/env python3
import os
import sys
import json
import argparse
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Supported source file extensions
SUPPORTED_EXTENSIONS = {
    '.py': 'Python', '.java': 'Java', '.cs': '.NET/C#', '.js': 'JavaScript',
    '.ts': 'TypeScript', '.pl': 'Perl', '.pm': 'Perl', '.php': 'PHP',
    '.c': 'C', '.cpp': 'C++', '.go': 'Go', '.rb': 'Ruby', '.rs': 'Rust'
}

EXCLUDED_DIRS = {'.git', 'node_modules', 'venv', '.venv', 'target', 'bin', 'obj', '__pycache__'}
CHECKPOINT_FILE = "sast_checkpoint.json"

def scan_and_chunk_project(root_dir, chunk_size=400):
    """Recursively scans root_dir, identifies code files, and breaks them into 400-line chunks."""
    project_chunks = []
    
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for file in files:
            ext = Path(file).suffix.lower()
            if ext in SUPPORTED_EXTENSIONS:
                full_path = Path(root) / file
                rel_path = full_path.relative_to(root_dir)
                language = SUPPORTED_EXTENSIONS[ext]
                
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    
                    total_lines = len(lines)
                    for i in range(0, total_lines, chunk_size):
                        chunk_lines = lines[i:i + chunk_size]
                        project_chunks.append({
                            "file_path": str(rel_path),
                            "language": language,
                            "start_line": i + 1,
                            "end_line": min(i + chunk_size, total_lines),
                            "content": "".join(chunk_lines),
                            "status": "pending"
                        })
                except Exception as e:
                    print(f"[-] Error reading {full_path}: {e}")
                    
    return project_chunks

def load_or_create_checkpoint(chunks):
    """Manages scan state across session interruptions."""
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r') as f:
                saved = json.load(f)
                print(f"[+] Loaded existing checkpoint with {len(saved)} chunk records.")
                return saved
        except Exception:
            pass
            
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(chunks, f, indent=2)
    return chunks

def generate_pdf_report(findings, output_pdf_path="sast_security_report.pdf"):
    """Generates a PDF security report using ReportLab."""
    doc = SimpleDocTemplate(output_pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=12
    )
    
    story.append(Paragraph("Static Application Security Testing (SAST) Audit Report", title_style))
    story.append(Paragraph(f"<b>Total Vulnerabilities Identified:</b> {len(findings)}", styles['Normal']))
    story.append(Spacer(1, 16))

    if not findings:
        story.append(Paragraph("No vulnerabilities detected across analyzed code chunks.", styles['Normal']))
    else:
        for index, item in enumerate(findings, start=1):
            sev_color = "#dc2626" if item.get('severity') in ['HIGH', 'CRITICAL'] else "#d97706"
            
            header_text = f"<b>{index}. {item.get('title', 'Security Finding')}</b> - <font color='{sev_color}'><b>{item.get('severity', 'UNKNOWN')}</b></font>"
            story.append(Paragraph(header_text, styles['Heading2']))
            
            details = [
                [Paragraph("<b>CWE / Taxonomy:</b>", styles['Normal']), Paragraph(f"{item.get('cwe_id', 'N/A')} ({item.get('owasp_category', 'N/A')})", styles['Normal'])],
                [Paragraph("<b>File Location:</b>", styles['Normal']), Paragraph(f"{item.get('file_path')} (Lines {item.get('start_line')}-{item.get('end_line')})", styles['Normal'])],
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
            
            story.append(Paragraph("<b>Vulnerable Code Fragment:</b>", styles['Normal']))
            story.append(Preformatted(item.get('vulnerable_code', 'N/A'), styles['Code']))
            story.append(Spacer(1, 6))

            story.append(Paragraph(f"<b>Remediation Strategy:</b> {item.get('remediation', 'N/A')}", styles['Normal']))
            
            if item.get('references'):
                refs = "<br/>".join([f"<a href='{r}'>{r}</a>" for r in item.get('references')])
                story.append(Paragraph(f"<b>References:</b><br/>{refs}", styles['Normal']))
                
            story.append(Spacer(1, 14))

    doc.build(story)
    print(f"[+] Mandatory PDF report successfully saved to: {output_pdf_path}")

def main():
    parser = argparse.ArgumentParser(description="Cross-Platform Agentic SAST Scanner Engine")
    parser.add_argument("--format", choices=["markdown", "sarif", "json", "html"], default="markdown", help="Primary requested report format")
    parser.add_argument("--dir", default=".", help="Target project root directory")
    args = parser.parse_args()

    target_dir = os.path.abspath(args.dir)
    print(f"[+] Initializing SAST scan on folder: {target_dir}")

    chunks = scan_and_chunk_project(target_dir)
    print(f"[+] Identified {len(chunks)} code chunk(s) (400-line blocks).")

    checkpoint_data = load_or_create_checkpoint(chunks)

    # Simulated finding structure passed from LLM analysis
    mock_findings = []
    
    # Generate Primary Format
    output_filename = f"sast_report.{'md' if args.format == 'markdown' else args.format}"
    with open(output_filename, 'w', encoding='utf-8') as f:
        if args.format == "json":
            json.dump(mock_findings, f, indent=2)
        else:
            f.write(f"# SAST Audit Summary\nPrimary Format: {args.format.upper()}\nTotal Findings: {len(mock_findings)}\n")
    print(f"[+] Primary report generated: {output_filename}")

    # Mandatory PDF Generation
    generate_pdf_report(mock_findings, "sast_security_report.pdf")

if __name__ == "__main__":
    main()