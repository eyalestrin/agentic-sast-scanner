# AGENTIC SAST SECURITY SCANNER SKILL

## STAGE 1: ENVIRONMENT & MODEL SELF-IDENTIFICATION
1. Inspect runtime traits and system parameters to establish your environment:
   - Identify your base model family (Anthropic/Claude, OpenAI/GPT, Google/Gemini, xAI/Grok, or Local/Ollama).
   - Recognize context capacity constraints and adapt token density accordingly.
2. Maintain strict output structure regardless of target runtime.

The generated reports must state the exact scanner model. This implementation uses no LLM during scanning and must report that fact as:
`No LLM model used; deterministic heuristic SAST rules`
Reports must also state every programming language detected from the scanned source files.

Detected external-agent integrations can be checked with:
`python3 ~/.vscode/skills/sast_engine.py --list-models`
The command prints only bare runtime model names. If an installed extension declares its model
in local source, the skill reports that model; otherwise it says that the
runtime model is unavailable. Extension versions must not be used as model
names.
For the connected WSL environment, confirm the underlying extension inventory with:
`code --list-extensions --show-versions`
Only extensions present in that output are currently installed for the remote
environment.
The active Copilot, Gemini, or Claude model and model version must be selected in its extension or CLI. Pass its exact displayed name to `--scanner-model` when rendering agent findings; the standalone renderer cannot discover or select runtime model versions.

Use `python3 ~/.vscode/skills/sast_engine.py --list-models` to display only
currently detected runtime model names. Pass the resulting model name to
`--scanner-model` when rendering agent findings.

When an external agent such as Copilot, Gemini, or Claude performs the semantic scan, it must create `~/.vscode/skills/agent_findings.json` using the documented JSON schema. The renderer uses that file with `--findings-input` and records `--scanner-model` only when agent findings are supplied. A model name without agent findings runs deterministic analysis and emits a warning; it must not be treated as an LLM scan.
When `--findings-input` is supplied but the file is missing, the engine must
stop; it must not label deterministic fallback findings as LLM findings.
If no Gemini terminal CLI is installed, the findings file must be created by
the active Gemini VS Code extension before invoking the renderer.
Selecting a model name without agent findings must not claim that model ran;
reports must show the requested model and the actual deterministic analysis
engine separately. Deterministic fix text is a context-dependent secure code
template, while exact copy/paste fixes require an agent-provided
`recommended_replacement`.
`agent_findings.json` is a per-scan artifact, not a permanent required skill
file. Deterministic scans do not need it, and agents must regenerate it when
the repository or selected model changes. Do not create an empty placeholder.
The canonical findings path is always `~/.vscode/skills/agent_findings.json`;
generated reports may be written elsewhere.

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