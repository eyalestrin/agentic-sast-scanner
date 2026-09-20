# Agentic SAST Scanner Skill

A cross-platform, LLM-agnostic Static Application Security Testing (SAST) skill designed for VS Code and its forks (Cursor, Windsurf, VSCodium, Positron). 

This skill automatically detects source code across all subdirectories, chunks large files into manageable 400-line blocks, tracks progress using local checkpoints, and evaluates security risks against **CWE**, **OWASP**, **CVSS v3.1**, and **MITRE ATT&CK** standards.

---

## Folder Layout

To operate properly, store the skill files in your workspace under the following structure:

```text
<your-project-root>/
└── .vscode/
    └── skills/
        ├── SKILL.md          # LLM instruction set and model self-identification rules
        ├── sast_engine.py    # Cross-platform Python scanner & PDF report engine
        └── README.md         # Installation and operational documentation  
```

---

## Step 1: Install System Prerequisites
Run the appropriate command in your terminal depending on your OS.  
1. Terminal Dependencies (Python & PDF Engine)  
   * Windows 11 (PowerShell or Windows Terminal):  
     ```PowerShell  
     python -m pip install reportlab markdown jinja2
     ```  
   * Linux (RHEL/Fedora):
     ```Bash
     sudo dnf install -y python3-reportlab python3-markdown python3-jinja2
     ```
   * Linux (Ubuntu 24.04+ / Debian 12+):  
     ```Bash  
     sudo apt update && sudo apt install -y python3-reportlab python3-markdown python3-jinja2
     ```  
   * macOS:  
     ```Bash  
     python3 -m pip install reportlab markdown jinja2
     ```  
2. VS Code Extensions  
   Install the YAML extension and your choice of AI Agent extension in VS Code:  
   ```Bash  
   code --install-extension redhat.vscode-yaml
   ```  

---

## Step 2: Installation & Setup Options
Clone Directly into `.vscode/skills`
If the `.vscode/skills` folder does not exist in your current target project, you can create it manually and clone this skill directly into it.
   * Windows 11 (PowerShell or Windows Terminal):
     Navigate to your target project's root folder and run:
	   ```PowerShell
     mkdir -p .vscode/skills
 	   git clone https://github.com/eyalestrin/agentic-sast-scanner.git .vscode/skills
     ```
   * Linux / macOS:  
	   Navigate to your target project's root folder and run:  
     ```Bash  
     mkdir -p .vscode/skills
     git clone https://github.com/eyalestrin/agentic-sast-scanner.git .vscode/skills
	   ```  

---

## Step 3: How to Run the Skill in VS Code

1. Open your project folder in **VS Code** (or any VS Code fork).  
2. Open the built-in terminal (`Ctrl + ~` on Windows/Linux, `Cmd + ~` on macOS).  
3. Execute the SAST engine specifying your primary output format choice (e.g., `sarif`, `markdown`, `json`, or `html`):  
   * Windows 11 (PowerShell or Windows Terminal):  
     ```PowerShell  
     python .vscode/skills/sast_engine.py --format html
     ```  
   * Linux / macOS:  
     ```Bash  
      python3 ~/.vscode/skills/sast_engine.py --format html
     ```
4. Before scanning, the engine removes previous report files. It processes all code files in subfolders in 400-line blocks, updates `sast_checkpoint.json`, produces only your requested format, and always generates `sast_security_report.pdf`.  

### Local scan with automatic JSON cleanup

Run the scanner from the folder where you want the reports to be written:

```Bash
python3 ~/.vscode/skills/sast_engine.py --dir /path/to/project --format html
```

The engine removes previous report files and the target's `sast_checkpoint.json` before scanning, then generates only the requested report plus the mandatory PDF. JSON and the checkpoint are deleted after a successful run. Use `--debug` to retain both for troubleshooting:

```Bash
python3 ~/.vscode/skills/sast_engine.py --dir /path/to/project --format html --debug
```

### Agent-driven scanning with Copilot, Gemini, or Claude

You do not need to write `agent_findings.json` manually. Ask the active
VS Code agent to inspect the repository and create the file. The Python
engine cannot call or switch the active VS Code model directly. The
`--scanner-model` option records which model performed the agent scan.

To see the currently supported agent integrations:

```Bash
python3 ~/.vscode/skills/sast_engine.py --list-models
```

This lists GitHub Copilot, Google Gemini, and Anthropic Claude integrations,
plus the deterministic fallback. When an extension is installed locally,
its extension version is shown. The active model and model version are
selected at runtime in the corresponding extension or CLI.

#### Agent instructions

Use the following prompt in Copilot Chat, Gemini Code Assist, or Claude:

```text
Use the Agentic SAST Scanner skill.
Scan this repository semantically for vulnerabilities.
Create agent_findings.json in the current folder using the schema in the
skill README. Include only focused vulnerable lines and provide an exact
copy/paste recommended_replacement for every finding.
```

The findings file must use this structure:

```json
{
  "findings": [
    {
      "title": "SQL injection",
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021-Injection",
      "severity": "HIGH",
      "file_path": "src/Repository.java",
      "start_line": 42,
      "end_line": 42,
      "vulnerable_code": "query = \"SELECT ... \" + userValue;",
      "remediation": "Use a parameterized query.",
      "recommended_replacement": "PreparedStatement statement = connection.prepareStatement(\"SELECT ... WHERE id = ?\"); statement.setString(1, userValue);",
      "references": ["https://cwe.mitre.org/data/definitions/89.html"]
    }
  ]
}
```

#### Renderer command

After the agent creates `agent_findings.json`, run the renderer from the
directory where reports should be written:

```Bash
python3 ~/.vscode/skills/sast_engine.py \
  --dir . \
  --findings-input agent_findings.json \
  --scanner-model "GPT-5.2-Copilot" \
  --format html
```

Change `--scanner-model` to the exact model selected in the agent
extension. Examples include `Gemini 2.5 Pro` and `Claude Sonnet 4`.
The engine validates and formats the agent findings; it does not claim
that deterministic rules used the external model.

```Bash
# Example: the active Gemini model is Gemini 2.5 Pro
python3 ~/.vscode/skills/sast_engine.py \
  --dir . \
  --findings-input agent_findings.json \
  --scanner-model "Gemini 2.5 Pro" \
  --format html
```

### Scan a remote Git repository without a persistent local checkout

Pass a remote repository URL with `--repo`. The engine creates a temporary shallow clone only for the scan, writes reports including the optional debug JSON to the current folder, and removes the temporary clone when finished:

```Bash
cd /path/for/reports
python3 ~/.vscode/skills/sast_engine.py \
  --repo https://github.com/organization/project.git \
  --format html
```

To scan a branch or tag and retain `sast_report.json` for troubleshooting:

```Bash
cd /path/for/reports
python3 ~/.vscode/skills/sast_engine.py \
  --repo https://github.com/organization/project.git \
  --ref main \
  --format markdown \
  --debug
```

The remote source is not kept as a checkout after the scan. The generated reports remain in the current folder. A Git client is required for `--repo` scans.

---

## Generated Artifacts

Once execution completes, the following files will be created in your project root directory:

| File Name | Purpose | Target Audience |
| :--- | :--- | :--- |
| `sast_report.<ext>` | Primary requested report (`.md`, `.sarif`, `.json`, or `.html`). | CI/CD Pipelines, GitHub Security Tab, IDE Inline Annotations. |
| `sast_security_report.pdf` | **Mandatory PDF Report** containing formatted vulnerability tables, vulnerable code snippets, fix diffs, and external references. | Security Lead, C-Level Management, Compliance Auditors. |
| `sast_checkpoint.json` | Temporary execution state tracker; deleted after successful runs unless `--debug` is used. | Debugging and verification. |
| `sast_report.json` | Validated intermediate/debug report; deleted after successful runs unless `--debug` is used. | Debugging and verification. |

---

## Troubleshooting & Tips

* **Resetting Scan State:** To force a fresh re-scan of the entire directory, delete the `sast_checkpoint.json` file in your root folder.
* **Excluding Extra Folders:** Modify `EXCLUDED_DIRS` inside `sast_engine.py` if you wish to skip specific build or asset directories.
* **Path Differences:** `sast_engine.py` uses Python's native `pathlib.Path` to normalize directory separators automatically between Windows ( `\` ) and POSIX systems ( `/` ).  