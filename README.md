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

You do not need to write `~/.vscode/skills/agent_findings.json` manually. Ask the active
VS Code agent to inspect the repository and create the file. The Python
engine cannot call or switch the active VS Code model directly. The
`--scanner-model` option records which model performed the agent scan.

`agent_findings.json` is not a permanent skill file and is not required for
deterministic scans. It is a per-scan input produced by the selected agent.
Do not create an empty placeholder: it would contain no agent findings and
would not represent a real LLM scan. The file should be regenerated when the
repository or selected model changes.

Location rule: always save agent findings at
`~/.vscode/skills/agent_findings.json`. Generated reports are written to the
current working directory, or the reports directory chosen by the command;
that is separate from the findings-file location.

To list only detected runtime LLM model names:

```Bash
python3 ~/.vscode/skills/sast_engine.py --list-models
```

When a runtime model name is exposed, output has this format:

```text
gemini-1.0-pro
```

The installed Gemini extension currently declares this runtime model:

```text
gemini-1.0-pro
```

Do not use the extension version as the model name. Use the runtime model
switch reported by the command.

#### Agent instructions

Use the following prompt in Copilot Chat, Gemini Code Assist, or Claude:

```text
Use the Agentic SAST Scanner skill.
Scan this repository semantically for vulnerabilities.
Create `~/.vscode/skills/agent_findings.json` using the schema in the
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

After the agent creates `~/.vscode/skills/agent_findings.json`, run
the renderer from the directory where reports should be written. A relative
findings path is not required; use the canonical skill-folder findings path:

The renderer does not invoke Gemini. If this file is missing, ask Gemini to
scan the repository and create it using the schema above before running the
following command.

The current environment has the Gemini VS Code extension but no `gemini`
terminal CLI. Therefore Gemini must create the findings file through the VS
Code extension; the Python renderer only validates and formats that file.

```Bash
python3 ~/.vscode/skills/sast_engine.py \
  --dir . \
  --scanner-model "GPT-5.2-Copilot" \
  --format html
```

When `--findings-input` is supplied, the renderer reads the canonical
skill-folder file and records `--scanner-model` in the reports. Supplying only
`--scanner-model` does not invoke an LLM; it runs deterministic analysis and
prints a warning.

Change `--scanner-model` to the exact model selected in the agent
extension. Examples include `Gemini 2.5 Pro` and `Claude Sonnet 4`.
The engine validates and formats the agent findings; it does not claim
that deterministic rules used the external model.

When `--findings-input` is supplied, the file is required. If it is missing,
the command stops with an actionable error instead of generating a
deterministic report labeled with the requested LLM model.

There are two valid modes:

1. Gemini-backed mode: Gemini creates `~/.vscode/skills/agent_findings.json`,
  then the renderer uses it with `--findings-input` and
  `--scanner-model gemini-1.0-pro`.
2. Deterministic mode: omit `--findings-input` and `--scanner-model`, or omit
  only `--findings-input` to receive a warning and use deterministic analysis.

The Python renderer cannot turn deterministic findings into Gemini findings.

#### Installed LLM model

List only the runtime model names detected in the installed LLM extensions:

```Bash
python3 ~/.vscode/skills/sast_engine.py --list-models
```

Current output:

```text
gemini-1.0-pro
```

Use that model name with the scanner switch:

```Bash
python3 ~/.vscode/skills/sast_engine.py \
  --dir . \
  --scanner-model "gemini-1.0-pro" \
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