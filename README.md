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

The engine removes previous report files before scanning and generates only the requested report plus the mandatory PDF. JSON is deleted after a successful JSON run. Use `--debug` to retain `sast_report.json` for troubleshooting:

```Bash
python3 ~/.vscode/skills/sast_engine.py --dir /path/to/project --format html --debug
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
| `sast_checkpoint.json` | Execution state tracker managing analyzed code chunks. | System / Internal Skill Engine. |
| `sast_report.json` | Validated intermediate/debug report; deleted after successful runs unless `--debug` is used. | Debugging and verification. |

---

## Troubleshooting & Tips

* **Resetting Scan State:** To force a fresh re-scan of the entire directory, delete the `sast_checkpoint.json` file in your root folder.
* **Excluding Extra Folders:** Modify `EXCLUDED_DIRS` inside `sast_engine.py` if you wish to skip specific build or asset directories.
* **Path Differences:** `sast_engine.py` uses Python's native `pathlib.Path` to normalize directory separators automatically between Windows ( `\` ) and POSIX systems ( `/` ).  