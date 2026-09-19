# AGENTIC SAST SECURITY SCANNER SKILL

## STAGE 1: ENVIRONMENT & MODEL SELF-IDENTIFICATION
1. Inspect runtime traits and system parameters to establish your environment:
   - Identify your base model family (Anthropic/Claude, OpenAI/GPT, Google/Gemini, xAI/Grok, or Local/Ollama).
   - Recognize context capacity constraints and adapt token density accordingly.
2. Maintain strict output structure regardless of target runtime.

## STAGE 2: EXECUTION & CHUNKING AGENTIC PROTOCOL
- Walk the project folder recursively.
- Filter out binary assets, dependency directories (`node_modules`, `vendor`, `.git`, `venv`, `target`, `bin`), and lockfiles.
- Automatically classify every programming language source file (`.py`, `.java`, `.pl`, `.cs`, `.js`, `.ts`, `.go`, `.rb`, `.cpp`, `.c`, `.php`).
- Process source code in **400-line chunks**.
- Read and update the local checkpoint file (`sast_checkpoint.json`) after each 400-line block to preserve progress across session restarts.

## STAGE 3: MULTI-LANGUAGE VULNERABILITY EVALUATION
For each 400-line block, scan for security weaknesses mapped to official standards:
- **Title:** Descriptive vulnerability name.
- **CWE / OWASP:** Exact CWE ID (e.g., CWE-89) and OWASP Top 10 category.
- **Severity Score:** Severity rating (CRITICAL, HIGH, MEDIUM, LOW) along with CVSS v3.1 vector string.
- **Location:** File path and exact physical line numbers.
- **Remediation:** Secure code snippet replacement.
- **References:** Official external URLs (OWASP Cheat Sheets, MITRE CWE, NIST).

## STAGE 4: OUTPUT ORCHESTRATION
- Prompt the user for their primary desired report format choice (`Markdown`, `SARIF`, `JSON`, or `HTML`).
- Execute `python .vscode/skills/sast_engine.py` to compile the findings.
- **Mandatory Policy:** The engine MUST generate the requested format AND automatically compile a `sast_security_report.pdf` report in all instances.