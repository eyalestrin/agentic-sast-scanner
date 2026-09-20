# AGENTIC SAST SECURITY SCANNER SKILL

## STAGE 1: ENVIRONMENT & MODEL SELF-IDENTIFICATION
1. Inspect runtime traits and system parameters to establish your environment:
   - Identify your base model family (Anthropic/Claude, OpenAI/GPT, Google/Gemini, xAI/Grok, or Local/Ollama).
   - Recognize context capacity constraints and adapt token density accordingly.
2. Maintain strict output structure regardless of target runtime.

The generated reports must state the exact scanner model. This implementation uses no LLM during scanning and must report that fact as:
`No LLM model used; deterministic heuristic SAST rules`
Reports must also state every programming language detected from the scanned source files.

Detected external-agent integrations and locally installed extension versions can be listed with:
`python3 ~/.vscode/skills/sast_engine.py --list-models`
The active Copilot, Gemini, or Claude model and model version must be selected in its extension or CLI. Pass its exact displayed name to `--scanner-model` when rendering agent findings; the standalone renderer cannot discover or select runtime model versions.

For GitHub Copilot, use the official VS Code extension `github.copilot-chat`,
sign in with GitHub, and verify Copilot Free eligibility in the GitHub account
plans/settings UI. The skill must not claim that a user has Copilot Free access
because account entitlements are private and unavailable to the Python renderer.

When an external agent such as Copilot, Gemini, or Claude performs the semantic scan, it must create `~/.vscode/skills/agent_findings.json` using the documented JSON schema and invoke the renderer with `--findings-input ~/.vscode/skills/agent_findings.json` and the exact `--scanner-model` value. The renderer must preserve the agent's `vulnerable_code` and `recommended_replacement` values. The Python engine cannot select or invoke the active VS Code model; `--scanner-model` is metadata identifying the model that the agent used.

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
- **Vulnerable Code:** The exact flagged source section and line range.
- **Remediation:** A concrete, language-appropriate copy/paste fix line; do not provide vague instructions such as “replace string”.
- **References:** Official external URLs (OWASP Cheat Sheets, MITRE CWE, NIST).

## STAGE 4: OUTPUT ORCHESTRATION
- Prompt the user for their primary desired report format choice (`Markdown`, `SARIF`, `JSON`, or `HTML`).
- Execute the engine using its absolute path fallback:
  `python3 ~/.vscode/skills/sast_engine.py --format <requested_format>`
  (or `python3 .vscode/skills/sast_engine.py` if cloned locally into the workspace).
- **Mandatory Policy:** The engine MUST generate the requested format AND automatically compile a `sast_security_report.pdf` report in all instances.
- Every output format (JSON, SARIF, Markdown, HTML, and PDF) MUST begin with the scanner model and detected programming languages.
- Every output format MUST include the exact vulnerable code, file path, start/end lines, and recommended replacement for each finding.
- Markdown, HTML, and PDF output MUST wrap long paths, URLs, code, and remediation text within the available window/page width.
- Before every scan, the engine MUST delete all previous report files (`sast_report.html`, `sast_report.md`, `sast_report.sarif`, `sast_report.json`, and `sast_security_report.pdf`).
- Before every scan, the engine MUST delete the target directory's `sast_checkpoint.json`; after successful completion it MUST delete that checkpoint unless debug mode is enabled.
- The engine MUST generate only the requested output format plus the mandatory PDF. `sast_report.json` may additionally be retained only when debug mode is explicitly enabled.
- Vulnerable-code output MUST contain only the focused matched snippet, never the full contents of a vulnerable source file.
- Each finding MUST include a language-appropriate copy/paste fix line that directly addresses the flagged operation.