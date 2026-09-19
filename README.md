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
     python -m pip install markdown reportlab jinja2  
     ```  
    * Linux (Ubuntu / Debian):  
      ```Bash  
      sudo apt update && sudo apt install -y python3 python3-pip  
      pip3 install markdown reportlab jinja2  
      ```  
    * macOS:  
      ```Bash  
      python3 -m pip install markdown reportlab jinja2  
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
	 git clone [https://github.com/eyalestrin/agentic-sast-scanner.git](https://github.com/eyalestrin/agentic-sast-scanner.git) .vscode/skills  
     ```  
    * Linux / macOS:  
	  Navigate to your target project's root folder and run:  
      ```Bash  
      mkdir -p .vscode/skills  
      git clone [https://github.com/eyalestrin/agentic-sast-scanner.git](https://github.com/eyalestrin/agentic-sast-scanner.git) .vscode/skills  
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
       python3 .vscode/skills/sast_engine.py --format sarif  
      ```  
4. The engine will run, process all code files in subfolders in 400-line blocks, update `sast_checkpoint.json`, produce your requested format file (`sast_report.html` or `sast_report.sarif`), and generate `sast_security_report.pdf`.  

---

## Generated Artifacts

Once execution completes, the following files will be created in your project root directory:

| File Name | Purpose | Target Audience |
| :--- | :--- | :--- |
| `sast_report.<ext>` | Primary requested report (`.md`, `.sarif`, `.json`, or `.html`). | CI/CD Pipelines, GitHub Security Tab, IDE Inline Annotations. |
| `sast_security_report.pdf` | **Mandatory PDF Report** containing formatted vulnerability tables, vulnerable code snippets, fix diffs, and external references. | Security Lead, C-Level Management, Compliance Auditors. |
| `sast_checkpoint.json` | Execution state tracker managing analyzed code chunks. | System / Internal Skill Engine. |

---

## Troubleshooting & Tips

* **Resetting Scan State:** To force a fresh re-scan of the entire directory, delete the `sast_checkpoint.json` file in your root folder.
* **Excluding Extra Folders:** Modify `EXCLUDED_DIRS` inside `sast_engine.py` if you wish to skip specific build or asset directories.
* **Path Differences:** `sast_engine.py` uses Python's native `pathlib.Path` to normalize directory separators automatically between Windows ( `\` ) and POSIX systems ( `/` ).  