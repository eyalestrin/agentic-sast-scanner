#!/usr/bin/env python3
"""
Agentic SAST Engine
-------------------
Handles directory traversal, 400-line chunking, state checkpointing,
built-in heuristic fallback scanning across Critical/High/Medium/Low severities,
schema validation, OWASP Cheat Sheet mapping, executive summary generation,
severity-based sorting, and multi-format (HTML, SARIF, JSON, Markdown, PDF) report generation.
"""

import os
import sys
import json
import re
import argparse
import shutil
import subprocess
import tempfile
from html import escape
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
JSON_REPORT_FILE = "sast_report.json"
AGENT_FINDINGS_FILE = Path(__file__).resolve().parent / "agent_findings.json"
REPORT_FILES = {
    "sast_report.html",
    "sast_report.md",
    "sast_report.sarif",
    "sast_report.json",
    "sast_security_report.pdf",
}
SCANNER_MODEL = "No LLM model used; deterministic heuristic SAST rules"
SUPPORTED_LLM_INTEGRATIONS = (
    ("GitHub Copilot", ("github.copilot", "Select the active Copilot model in VS Code; pass its exact displayed name with --scanner-model.")),
    ("Google Gemini", ("gemini", "Select the active Gemini model in Gemini Code Assist; pass its exact displayed name with --scanner-model.")),
    ("Anthropic Claude", ("claude", "Select the active Claude model in the Claude extension or CLI; pass its exact displayed name with --scanner-model.")),
)

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3
}

# Static heuristic fallback rules with validated reference URLs
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
            "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
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
            "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
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

def sort_findings(findings):
    """Sorts findings by severity rank: CRITICAL -> HIGH -> MEDIUM -> LOW."""
    return sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'MEDIUM').upper(), 99))

def get_severity_counts(findings):
    """Generates a dictionary with counts per severity level."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in findings:
        sev = item.get('severity', 'MEDIUM').upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["MEDIUM"] += 1
    return counts


RECOMMENDED_FIXES = {
    "CWE-78": "subprocess.run([command, argument], shell=False, check=True)",
    "CWE-89": "prepared_statement = connection.prepareStatement(\"SELECT column FROM table WHERE id = ?\"); prepared_statement.setString(1, user_value)",
    "CWE-918": "allowed_url = validate_against_allowlist(request_url); response = requests.get(allowed_url, timeout=5)",
    "CWE-22": "safe_path = Path(base_dir, user_path).resolve(); assert safe_path.is_relative_to(Path(base_dir).resolve())",
    "CWE-532": "logger.info(\"Request for key=%s\", mask_secret(secret_key))",
    "CWE-352": "http.csrf(csrf -> csrf.csrfTokenRepository(tokenRepository))",
    "CWE-396": "except (IOException error): handle_input_error(error)",
}

LANGUAGE_FIXES = {
    "JavaScript": {
        "CWE-78": "execFile(command, [argument], { shell: false }, callback);",
        "CWE-89": "const statement = db.prepare('SELECT column FROM table WHERE id = ?'); statement.get(userValue);",
        "CWE-918": "const response = await fetch(allowlistedUrl, { signal: AbortSignal.timeout(5000) });",
        "CWE-22": "const safePath = path.resolve(baseDir, userPath); if (!safePath.startsWith(path.resolve(baseDir) + path.sep)) throw new Error('Invalid path');",
        "CWE-532": "logger.info('Request for key=%s', maskSecret(secretKey));",
        "CWE-352": "app.use(csrf({ cookie: { httpOnly: true, sameSite: 'strict' } }));",
        "CWE-396": "catch (error) { handleInputError(error); }",
    },
    "Java": {
        "CWE-78": "new ProcessBuilder(command, argument).start();",
        "CWE-89": "PreparedStatement statement = connection.prepareStatement(\"SELECT column FROM table WHERE id = ?\"); statement.setString(1, userValue);",
        "CWE-918": "URI allowedUri = validateAgainstAllowlist(requestUri);",
        "CWE-22": "Path safePath = Path.of(baseDir, userPath).toRealPath(); if (!safePath.startsWith(Path.of(baseDir).toRealPath())) throw new SecurityException();",
        "CWE-532": "logger.info(\"Request for key={}\", maskSecret(secretKey));",
        "CWE-352": "http.csrf(csrf -> csrf.csrfTokenRepository(tokenRepository));",
        "CWE-396": "catch (IOException error) { handleInputError(error); }",
    },
}


def get_recommended_fix(finding):
    """Returns a concrete copy-paste replacement line for a finding's CWE."""
    if finding.get("recommended_replacement"):
        return str(finding["recommended_replacement"])
    extension = Path(str(finding.get("file_path", ""))).suffix.lower()
    language = SUPPORTED_EXTENSIONS.get(extension)
    if language in LANGUAGE_FIXES and finding.get("cwe_id") in LANGUAGE_FIXES[language]:
        return LANGUAGE_FIXES[language][finding["cwe_id"]]
    return RECOMMENDED_FIXES.get(
        finding.get("cwe_id"),
        "secure_value = validate_untrusted_input(raw_value)"
    )


def detect_languages(target_dir):
    """Returns the programming languages detected in supported source files."""
    languages = set()
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for file in files:
            language = SUPPORTED_EXTENSIONS.get(Path(file).suffix.lower())
            if language:
                languages.add(language)
    return sorted(languages)


def build_report_metadata(target_dir, scanner_model=None):
    """Builds metadata that must appear in every report format."""
    languages = detect_languages(target_dir)
    return {
        "scanner_model": scanner_model or SCANNER_MODEL,
        "detected_languages": languages or ["None detected"],
    }


def load_agent_findings(findings_path):
    """Loads findings produced by Copilot, Gemini, Claude, or another external agent."""
    findings_file = Path(findings_path)
    if not findings_file.is_file():
        raise FileNotFoundError(
            f"Agent findings file not found in the skill folder: {findings_file.resolve()}. "
            "Ask the selected LLM agent to create agent_findings.json first, "
            "or provide the correct path with --findings-input."
        )
    with open(findings_file, 'r', encoding='utf-8') as handle:
        data = json.load(handle)
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        raise ValueError("Agent findings input must be a list or an object with a findings list.")
    if not isinstance(findings, list):
        raise ValueError("Agent findings input must contain a findings list.")
    return sort_findings([compact_finding_code(dict(item)) for item in findings])


def discover_agent_extensions():
    """Finds installed agent extensions and their package versions on this machine."""
    extension_roots = [Path.home() / ".vscode-server" / "extensions", Path.home() / ".vscode" / "extensions"]
    if os.environ.get("VSCODE_EXTENSIONS"):
        extension_roots.insert(0, Path(os.environ["VSCODE_EXTENSIONS"]))
    discovered = {}
    for root in extension_roots:
        if not root or not root.is_dir():
            continue
        for extension_dir in root.iterdir():
            package_path = extension_dir / "package.json"
            if not package_path.is_file():
                continue
            try:
                package = json.loads(package_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            extension_id = f"{package.get('publisher', '')}.{package.get('name', '')}".lower()
            for provider, (identifier, _) in SUPPORTED_LLM_INTEGRATIONS:
                if identifier in extension_id or identifier in extension_dir.name.lower():
                    discovered[provider] = {
                        "extension_id": extension_id,
                        "extension_version": package.get("version", "unknown"),
                    }

    code_cli = shutil.which("code")
    if code_cli:
        try:
            result = subprocess.run(
                [code_cli, "--list-extensions", "--show-versions"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in result.stdout.splitlines():
                extension_id, separator, version = line.strip().partition("@")
                if not separator:
                    continue
                for provider, (identifier, _) in SUPPORTED_LLM_INTEGRATIONS:
                    if identifier in extension_id.lower():
                        discovered[provider] = {
                            "extension_id": extension_id,
                            "extension_version": version,
                        }
        except (OSError, subprocess.TimeoutExpired):
            pass
    return discovered


def print_supported_models():
    """Prints only LLM integrations detected on this machine."""
    installed = discover_agent_extensions()
    print("Currently supported LLM integrations detected on this machine:")
    if not installed:
        print("- None detected")
        return
    for provider, (_, instruction) in SUPPORTED_LLM_INTEGRATIONS:
        details = installed.get(provider)
        if details:
            print(f"- {provider}: {details['extension_id']} version {details['extension_version']}")
            print(f"  {instruction}")


def resolve_findings_path(findings_path, target_dir):
    """Resolves relative findings from the skill directory."""
    requested_path = Path(findings_path).expanduser()
    if requested_path.is_absolute():
        return str(requested_path)
    if requested_path.name == AGENT_FINDINGS_FILE.name:
        return str(AGENT_FINDINGS_FILE)
    return str(Path(__file__).resolve().parent / requested_path)


def finding_report_data(finding):
    """Returns the exact source location, code, and replacement guidance."""
    return {
        "file_path": finding.get("file_path"),
        "start_line": finding.get("start_line"),
        "end_line": finding.get("end_line"),
        "vulnerable_code": finding.get("vulnerable_code"),
        "recommended_replacement": get_recommended_fix(finding),
    }


def cleanup_previous_reports():
    """Removes all report artifacts before a new scan starts."""
    for report_name in REPORT_FILES:
        report_path = Path.cwd() / report_name
        if report_path.exists():
            report_path.unlink()
            print(f"[+] Removed previous report: {report_path}")


def cleanup_checkpoint(target_dir):
    """Removes the scan checkpoint from the target directory."""
    checkpoint_path = Path(target_dir) / CHECKPOINT_FILE
    if checkpoint_path.exists():
        checkpoint_path.unlink()
        print(f"[+] Removed scan checkpoint: {checkpoint_path}")


def compact_vulnerable_code(code, rule_pattern=None, max_length=1200):
    """Keeps a focused matching region when a source line is unusually large."""
    code = str(code or "").strip()
    if len(code) <= max_length:
        return code

    match = re.search(rule_pattern, code, re.IGNORECASE) if rule_pattern else None
    if match:
        context = 240
        start = max(0, match.start() - context)
        if match.end() - match.start() > context:
            end = min(len(code), match.start() + context)
        else:
            end = min(len(code), match.end() + context)
        snippet = code[start:end]
        prefix = "..." if start else ""
        suffix = "..." if end < len(code) else ""
        return f"{prefix}{snippet}{suffix}"
    return f"{code[:max_length]}..."


def compact_finding_code(finding):
    """Compacts a finding using the matching rule while preserving its source location."""
    matched_rule = None
    for rule in STATIC_HEURISTIC_RULES:
        if rule["title"] == finding.get("title"):
            matched_rule = rule
            break
    finding["vulnerable_code"] = compact_vulnerable_code(
        finding.get("vulnerable_code"), matched_rule["pattern"] if matched_rule else None
    )
    return finding


def prepare_scan_target(repo_url=None, ref=None, target_dir=None):
    """Returns a scan directory and temporary clone path for an optional remote repository."""
    if not repo_url:
        return os.path.abspath(target_dir or "."), None

    temporary_dir = tempfile.mkdtemp(prefix="agentic-sast-")
    clone_command = ["git", "clone", "--depth", "1", "--filter", "blob:none"]
    if ref:
        clone_command.extend(["--branch", ref])
    clone_command.extend([repo_url, temporary_dir])
    try:
        subprocess.run(clone_command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        shutil.rmtree(temporary_dir, ignore_errors=True)
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        raise RuntimeError(f"Unable to scan remote Git repository: {detail}") from error

    print(f"[+] Remote repository cloned temporarily for scanning: {repo_url}")
    return temporary_dir, temporary_dir


def write_json_report(findings, metadata, output_path=JSON_REPORT_FILE):
    """Writes and validates the JSON report used as the optional debug artifact."""
    report_findings = []
    for item in findings:
        report_item = dict(item)
        report_item.update(finding_report_data(item))
        report_findings.append(report_item)
    with open(output_path, 'w', encoding='utf-8') as handle:
        json.dump({"metadata": metadata, "findings": report_findings}, handle, indent=2)
    validate_report_output("json", output_path, findings, metadata)


def validate_findings(findings):
    """Validates the structure and required fields of the generated findings list."""
    if not isinstance(findings, list):
        raise ValueError("Findings must be stored in a list.")

    required_fields = {
        "title",
        "cwe_id",
        "owasp_category",
        "severity",
        "file_path",
        "start_line",
        "end_line",
        "vulnerable_code",
        "remediation",
        "references",
    }

    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            raise ValueError(f"Finding #{index} is not a dictionary: {type(item).__name__}")

        missing = sorted(required_fields - set(item.keys()))
        if missing:
            raise ValueError(f"Finding #{index} is missing required keys: {', '.join(missing)}")

        if not isinstance(item.get("references", []), list):
            raise ValueError(f"Finding #{index} references must be a list.")

        if len(str(item.get("vulnerable_code", ""))) > 1200:
            raise ValueError(f"Finding #{index} contains an oversized vulnerable-code snippet.")

    return True


def validate_report_output(report_type, output_path, findings, metadata):
    """Ensures a generated report file exists, is non-empty, and matches the expected findings summary."""
    validate_findings(findings)

    if not os.path.exists(output_path):
        raise ValueError(f"{report_type.upper()} report was not created on disk: {output_path}")

    file_size = os.path.getsize(output_path)
    if file_size <= 0:
        raise ValueError(f"{report_type.upper()} report is empty: {output_path}")

    counts = get_severity_counts(findings)
    expected_model = metadata["scanner_model"]
    expected_languages = metadata["detected_languages"]

    if report_type == "json":
        with open(output_path, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or "metadata" not in data or "findings" not in data:
            raise ValueError("JSON report must contain metadata and findings sections.")
        if data["metadata"].get("scanner_model") != expected_model or data["metadata"].get("detected_languages") != expected_languages:
            raise ValueError("JSON report metadata does not match the scan.")
        if len(data["findings"]) != len(findings):
            raise ValueError(f"JSON report mismatch: expected {len(findings)} findings, found {len(data['findings'])}")
        if any("vulnerable_code" not in item or "recommended_replacement" not in item for item in data["findings"]):
            raise ValueError("JSON report is missing exact code or replacement details.")

    elif report_type == "sarif":
        with open(output_path, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
        if "runs" not in data or not data["runs"]:
            raise ValueError("SARIF report is missing the runs section.")
        properties = data["runs"][0].get("properties", {})
        if properties.get("scanner_model") != expected_model or properties.get("detected_languages") != expected_languages:
            raise ValueError("SARIF report metadata does not match the scan.")
        result_count = len(data["runs"][0].get("results", []))
        if result_count != len(findings):
            raise ValueError(f"SARIF report mismatch: expected {len(findings)} results, found {result_count}")
        if any("vulnerable_code" not in result.get("properties", {}) or "recommended_replacement" not in result.get("properties", {}) for result in data["runs"][0]["results"]):
            raise ValueError("SARIF report is missing exact code or replacement details.")

    elif report_type == "html":
        content = Path(output_path).read_text(encoding='utf-8', errors='ignore')
        required_tokens = ["Static Application Security Testing (SAST) Audit Report", "Executive Summary", "Detailed Security Findings", f"Total Vulnerabilities Identified:</b> {len(findings)}", escape(expected_model), "Detected Languages"]
        if findings:
            required_tokens.extend(["Focused Vulnerable Code:", "Copy/Paste Fix:"])
        required_tokens.extend(escape(language) for language in expected_languages)
        for token in required_tokens:
            if token not in content:
                raise ValueError(f"HTML report is missing required token: {token}")
        rendered_rows = content.count('<tr class="finding-row">')
        if rendered_rows != len(findings):
            raise ValueError(f"HTML report mismatch: expected {len(findings)} finding rows, found {rendered_rows}")
        if content.count("Focused Vulnerable Code:") != len(findings) or content.count("Copy/Paste Fix:") != len(findings):
            raise ValueError("HTML report is missing exact code or replacement details.")
        for severity, total in counts.items():
            if f'{severity}</span></td><td><b>{total}</b>' not in content and f'{severity}</b></font>' not in content:
                raise ValueError(f"HTML summary count mismatch for {severity}: expected {total}")

    elif report_type == "markdown":
        content = Path(output_path).read_text(encoding='utf-8', errors='ignore')
        required_tokens = ["# SAST Audit Summary", f"Scanner Model: **{expected_model}**", "Detected Languages:"]
        required_tokens.extend(f"- {language}" for language in expected_languages)
        if findings:
            required_tokens.extend(["Focused Vulnerable Code:", "Copy/Paste Fix:"])
        if any(token not in content for token in required_tokens):
            raise ValueError("Markdown report is missing the summary header.")
        if f"Total Vulnerabilities Identified: **{len(findings)}**" not in content:
            raise ValueError(f"Markdown report mismatch: expected {len(findings)} findings")
        if content.count("Focused Vulnerable Code:") != len(findings) or content.count("Copy/Paste Fix:") != len(findings):
            raise ValueError("Markdown report is missing exact code or replacement details.")

    elif report_type == "pdf":
        with open(output_path, 'rb') as handle:
            header = handle.read(5)
        if header != b'%PDF-':
            raise ValueError(f"PDF report is invalid or incomplete: {output_path}")

    else:
        raise ValueError(f"Unsupported report validation type: {report_type}")

    return True


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
                "vulnerable_code": compact_vulnerable_code(line, rule["pattern"]),
                "remediation": rule["remediation"],
                "references": rule["references"]
            })
    return findings

def load_or_scan_checkpoint(target_dir):
    """Loads valid vulnerability findings from sast_checkpoint.json or runs fallback scan."""
    checkpoint_path = Path(target_dir) / CHECKPOINT_FILE
    if checkpoint_path.exists():
        try:
            with open(checkpoint_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                raw_findings = []
                if isinstance(data, list):
                    raw_findings = data
                elif isinstance(data, dict) and "findings" in data:
                    raw_findings = data["findings"]
                
                valid_findings = [
                    item for item in raw_findings 
                    if isinstance(item, dict) and ("title" in item or "cwe_id" in item or "vulnerable_code" in item)
                ]

                if valid_findings:
                    return sort_findings([compact_finding_code(item) for item in valid_findings])
                else:
                    print("[-] Found checkpoint file, but it contains raw chunk metadata instead of vulnerability findings. Running fallback scan...")
        except Exception as e:
            print(f"[-] Warning: Failed to parse existing {checkpoint_path}: {e}")

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

    sorted_findings = sort_findings(findings)

    # Persist verified findings checkpoint
    with open(checkpoint_path, 'w', encoding='utf-8') as f:
        json.dump({"chunks": chunks_count, "findings": sorted_findings}, f, indent=2)

    return sorted_findings

def generate_pdf_report(findings, metadata, output_pdf_path="sast_security_report.pdf"):
    """Generates mandatory PDF security report with Executive Summary using ReportLab."""
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
    wrapped_code_style = ParagraphStyle(
        'WrappedCode', parent=styles['Code'], fontSize=7, leading=8, wordWrap='CJK'
    )

    story.append(Paragraph("Static Application Security Testing (SAST) Audit Report", title_style))
    story.append(Paragraph(f"<b>Scanner Model:</b> {escape(metadata['scanner_model'])}", styles['Normal']))
    story.append(Paragraph(f"<b>Detected Languages:</b> {escape(', '.join(metadata['detected_languages']))}", styles['Normal']))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Executive Summary", styles['Heading2']))
    story.append(Paragraph(f"<b>Total Vulnerabilities Identified:</b> {len(findings)}", styles['Normal']))
    story.append(Spacer(1, 8))

    counts = get_severity_counts(findings)
    summary_table_data = [
        [Paragraph("<b>Severity Level</b>", styles['Normal']), Paragraph("<b>Identified Count</b>", styles['Normal'])],
        [Paragraph("<font color='#dc2626'><b>Critical</b></font>", styles['Normal']), Paragraph(str(counts['CRITICAL']), styles['Normal'])],
        [Paragraph("<font color='#ea580c'><b>High</b></font>", styles['Normal']), Paragraph(str(counts['HIGH']), styles['Normal'])],
        [Paragraph("<font color='#d97706'><b>Medium</b></font>", styles['Normal']), Paragraph(str(counts['MEDIUM']), styles['Normal'])],
        [Paragraph("<font color='#2563eb'><b>Low</b></font>", styles['Normal']), Paragraph(str(counts['LOW']), styles['Normal'])],
    ]

    summary_table = Table(summary_table_data, colWidths=[200, 300])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Detailed Security Findings", styles['Heading2']))
    story.append(Spacer(1, 8))

    if not findings:
        story.append(Paragraph("No security vulnerabilities detected across project code chunks.", styles['Normal']))
    else:
        for index, item in enumerate(findings, start=1):
            sev = item.get('severity', 'MEDIUM').upper()
            if sev == 'CRITICAL':
                sev_color = "#dc2626"
            elif sev == 'HIGH':
                sev_color = "#ea580c"
            elif sev == 'MEDIUM':
                sev_color = "#d97706"
            else:
                sev_color = "#2563eb"

            header_text = f"<b>{index}. {item.get('title', 'Security Finding')}</b> - <font color='{sev_color}'><b>{sev}</b></font>"
            story.append(Paragraph(header_text, styles['Heading3']))

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

            story.append(Paragraph("<b>Focused Vulnerable Code:</b>", styles['Normal']))
            story.append(Paragraph(escape(str(item.get('vulnerable_code', 'N/A'))), wrapped_code_style))
            story.append(Spacer(1, 6))

            story.append(Paragraph("<b>Copy/Paste Fix:</b>", styles['Normal']))
            story.append(Paragraph(escape(get_recommended_fix(item)), wrapped_code_style))
            story.append(Spacer(1, 6))

            story.append(Paragraph(f"<b>Remediation Strategy:</b> {item.get('remediation', 'N/A')}", styles['Normal']))

            if item.get('references'):
                refs = "<br/>".join([f"<a href='{r}'>{r}</a>" for r in item.get('references')])
                story.append(Paragraph(f"<b>References:</b><br/>{refs}", styles['Normal']))

            story.append(Spacer(1, 14))

    doc.build(story)
    validate_report_output("pdf", output_pdf_path, findings, metadata)
    print(f"[+] Mandatory PDF report generated: {output_pdf_path}")
    return output_pdf_path

def generate_html_report(findings, metadata, output_html_path="sast_report.html"):
    """Generates HTML report with Executive Summary table."""
    counts = get_severity_counts(findings)
    rows = ""
    for item in findings:
        sev = escape(str(item.get('severity', 'MEDIUM')).upper())
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
            refs_html = "<br/><small>" + "<br/>".join(
                [f"<a href='{escape(str(r), quote=True)}' target='_blank'>{escape(str(r))}</a>" for r in item.get('references')]
            ) + "</small>"

        current_code = escape(str(item.get('vulnerable_code', '')))
        recommended_fix = escape(get_recommended_fix(item))

        rows += f"""
        <tr class="finding-row">
            <td><span class="badge {badge_class}">{sev}</span></td>
            <td><b>{escape(str(item.get('title', '')))}</b><br/><small>{escape(str(item.get('cwe_id', '')))} | {escape(str(item.get('owasp_category', '')))}</small></td>
            <td><code>{escape(str(item.get('file_path', '')))}:{escape(str(item.get('start_line', '')))}-{escape(str(item.get('end_line', '')))}</code></td>
            <td>
                <b>Focused Vulnerable Code:</b>
                <pre><code>{current_code}</code></pre>
                <b>Copy/Paste Fix:</b>
                <pre><code>{recommended_fix}</code></pre>
            </td>
            <td><b>Remediation:</b> {escape(str(item.get('remediation', '')))}{refs_html}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Static Application Security Testing (SAST) Audit Report</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background: #f8fafc; color: #0f172a; max-width: 100%; overflow-x: hidden; }}
        h1, h2 {{ color: #0f172a; }}
        table {{ width: 100%; max-width: 100%; table-layout: fixed; border-collapse: collapse; margin-top: 12px; margin-bottom: 24px; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }}
        th {{ background: #f1f5f9; }}
        pre {{ background: #0f172a; color: #f8fafc; padding: 8px; border-radius: 4px; max-width: 100%; margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; font-size: 12px; }}
        code {{ overflow-wrap: anywhere; word-break: break-word; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; color: white; }}
        .critical {{ background: #dc2626; }}
        .high {{ background: #ea580c; }}
        .medium {{ background: #d97706; }}
        .low {{ background: #2563eb; }}
        .summary-table {{ width: 50%; min-width: 280px; }}
        @media (max-width: 800px) {{
            body {{ margin: 10px; }}
            h1 {{ font-size: 1.45rem; }}
            h2 {{ font-size: 1.15rem; }}
            th, td {{ padding: 7px; font-size: 0.85rem; }}
            pre {{ font-size: 10px; padding: 5px; }}
            .summary-table {{ width: 100%; min-width: 0; }}
        }}
    </style>
</head>
<body>
    <h1>Static Application Security Testing (SAST) Audit Report</h1>
    <p><b>Scanner Model:</b> {escape(metadata['scanner_model'])}</p>
    <p><b>Detected Languages:</b> {escape(', '.join(metadata['detected_languages']))}</p>
    
    <h2>Executive Summary</h2>
    <p><b>Total Vulnerabilities Identified:</b> {len(findings)}</p>
    <table class="summary-table">
        <thead>
            <tr>
                <th>Severity Level</th>
                <th>Identified Count</th>
            </tr>
        </thead>
        <tbody>
            <tr><td><span class="badge critical">CRITICAL</span></td><td><b>{counts['CRITICAL']}</b></td></tr>
            <tr><td><span class="badge high">HIGH</span></td><td><b>{counts['HIGH']}</b></td></tr>
            <tr><td><span class="badge medium">MEDIUM</span></td><td><b>{counts['MEDIUM']}</b></td></tr>
            <tr><td><span class="badge low">LOW</span></td><td><b>{counts['LOW']}</b></td></tr>
        </tbody>
    </table>

    <h2>Detailed Security Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Vulnerability & Taxonomy</th>
                <th>Location</th>
                <th>Focused Vulnerable Code & Copy/Paste Fix</th>
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
    validate_report_output("html", output_html_path, findings, metadata)
    print(f"[+] HTML report generated: {output_html_path}")
    return output_html_path

def generate_sarif_report(findings, metadata, output_sarif_path="sast_report.sarif"):
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
            }],
            "properties": finding_report_data(item)
        })

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "properties": metadata,
        "runs": [{
            "properties": metadata,
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
    validate_report_output("sarif", output_sarif_path, findings, metadata)
    print(f"[+] SARIF report generated: {output_sarif_path}")
    return output_sarif_path

def main():
    parser = argparse.ArgumentParser(description="Cross-Platform Agentic SAST Engine")
    parser.add_argument("--format", choices=["markdown", "sarif", "json", "html"], default="html")
    parser.add_argument("--list-models", action="store_true", help="List supported LLM agent integrations and exit")
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--dir", default=".", help="Local directory to scan")
    target_group.add_argument("--repo", help="Remote Git repository URL to scan temporarily")
    parser.add_argument("--ref", help="Branch, tag, or commit ref for --repo")
    parser.add_argument("--debug", action="store_true", help="Keep sast_report.json after a successful scan")
    parser.add_argument("--findings-input", help="JSON findings file produced by Copilot, Gemini, Claude, or another agent")
    parser.add_argument("--scanner-model", help="Exact model name used to produce --findings-input")
    args = parser.parse_args()

    if args.list_models:
        print_supported_models()
        return

    if args.findings_input and not args.scanner_model:
        parser.error("--scanner-model is required when --findings-input is used")

    cleanup_previous_reports()
    target_dir, temporary_dir = prepare_scan_target(args.repo, args.ref, args.dir)
    try:
        cleanup_checkpoint(target_dir)
        print(f"[+] Initializing SAST Engine on target folder: {target_dir}")

        findings_model = args.scanner_model
        if args.findings_input:
            findings_path = resolve_findings_path(args.findings_input, target_dir)
            try:
                findings = load_agent_findings(findings_path)
            except FileNotFoundError as error:
                print(f"[!] {error}")
                print("[!] Running deterministic fallback; this report will not claim that Gemini scanned the code.")
                findings = load_or_scan_checkpoint(target_dir)
                findings_model = None
            else:
                print(f"[+] Loaded agent findings from: {findings_path}")
        else:
            findings = load_or_scan_checkpoint(target_dir)
        metadata = build_report_metadata(target_dir, findings_model)
        print(f"[+] Active vulnerability findings loaded: {len(findings)}")
        print(f"[+] Scanner model: {metadata['scanner_model']}")
        print(f"[+] Detected languages: {', '.join(metadata['detected_languages'])}")

        if args.format == "json" or args.debug:
            write_json_report(findings, metadata)
            print("[+] Validated JSON report generated: sast_report.json")

        if args.format == "html":
            generate_html_report(findings, metadata, "sast_report.html")
        elif args.format == "sarif":
            generate_sarif_report(findings, metadata, "sast_report.sarif")
        elif args.format == "json":
            print("[+] Primary JSON report generated: sast_report.json")
        else:
            out_name = f"sast_report.{'md' if args.format == 'markdown' else args.format}"
            counts = get_severity_counts(findings)
            with open(out_name, 'w', encoding='utf-8') as f:
                f.write("# SAST Audit Summary\n\n")
                f.write(f"- Scanner Model: **{metadata['scanner_model']}**\n")
                f.write("- Detected Languages:\n")
                for language in metadata["detected_languages"]:
                    f.write(f"  - {language}\n")
                f.write("\n")
                f.write("## Executive Summary\n")
                f.write(f"- Total Vulnerabilities Identified: **{len(findings)}**\n")
                f.write(f"- Critical: {counts['CRITICAL']} | High: {counts['HIGH']} | Medium: {counts['MEDIUM']} | Low: {counts['LOW']}\n\n")
                f.write("## Detailed Findings\n")
                for item in findings:
                    f.write(f"### {item.get('title')} ({item.get('severity')})\n")
                    f.write(f"- Location: `{item.get('file_path')}:{item.get('start_line')}-{item.get('end_line')}`\n")
                    f.write(f"- CWE: {item.get('cwe_id')}\n\n")
                    f.write("**Focused Vulnerable Code:**\n\n")
                    f.write(f"<pre style=\"white-space: pre-wrap; overflow-wrap: anywhere;\">{escape(str(item.get('vulnerable_code', '')))}</pre>\n\n")
                    f.write("**Copy/Paste Fix:**\n\n")
                    f.write(f"<pre style=\"white-space: pre-wrap; overflow-wrap: anywhere;\">{escape(get_recommended_fix(item))}</pre>\n\n")
            validate_report_output("markdown", out_name, findings, metadata)
            print(f"[+] Primary report generated: {out_name}")

        generate_pdf_report(findings, metadata, "sast_security_report.pdf")
        if args.debug:
            print("[+] Debug mode enabled; keeping sast_report.json")
        else:
            if args.format == "json":
                report_path = Path.cwd() / JSON_REPORT_FILE
                if report_path.exists():
                    report_path.unlink()
                    print("[+] Scan completed successfully; deleted sast_report.json")
        if args.debug:
            print("[+] Debug mode enabled; keeping sast_checkpoint.json")
        else:
            cleanup_checkpoint(target_dir)
            print("[+] Scan completed successfully; deleted sast_checkpoint.json")
    finally:
        if temporary_dir:
            shutil.rmtree(temporary_dir, ignore_errors=True)
            print("[+] Removed temporary remote repository copy")

if __name__ == "__main__":
    main()