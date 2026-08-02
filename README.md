# Autonomous Patch Management Agent

A fully local, AI-powered Windows patch management agent built with Python and OLLAMA.
The agent autonomously detects, assesses, installs, monitors, diagnoses, and fixes
Microsoft Windows patches — with zero human intervention for everything the system
can handle safely.

---

## What it does

- Detects new Microsoft Windows patches automatically every 6 hours
- Checks every new patch for known bugs before downloading
- If bugs are found — performs root cause analysis and attempts to fix the issue first
- Only downloads and installs the patch after the root cause is resolved
- If root cause cannot be fixed — skips the patch and gives the user detailed manual instructions
- Uses a local LLM (Phi-3 Mini via OLLAMA) to assess patch risk before installing
- Installs Low and Medium risk patches autonomously
- Monitors Windows Event Log for errors after every patch install
- Diagnoses errors using AI and applies fixes automatically (DISM, service restart)
- Uses a permanent error cache — known errors are fixed instantly without calling the LLM
- Only calls the LLM for brand new errors it has never seen before
- Only escalates to the user when the issue genuinely requires human intervention
- Audits all historically installed patches for newly discovered bugs
- If a bug is found in an installed patch — attempts to fix it first, then uninstalls if fix fails
- Generates a single combined HTML report after every cycle covering everything
- Runs entirely offline — no cloud, no API keys, no data leaves your machine

---

## Performance

| Scenario | Cycle time |
|----------|-----------|
| All errors known (cache hits) | Under 2 minutes |
| Mix of cached and new errors | 3 to 10 minutes |
| All new errors (first run) | 5 to 15 minutes |
| DISM repair needed | 10 to 30 minutes |

After the first run, most cycles complete in under 2 minutes because the error cache eliminates LLM calls for recurring errors.

---

## How the error cache works

```
Error comes in
      ↓
Check local cache first (instant)
      ↓
Cache hit? → Use saved fix directly — zero LLM time
      ↓
No cache entry? → Send to LLM → Save result permanently
      ↓
Same error next cycle → Cache hit — no LLM call ever again
      ↓
If cached fix fails 3 times → Cache entry deleted → LLM re-diagnoses
```

The cache never expires. Once an error is diagnosed, that diagnosis is used forever unless the fix stops working.

---

## How the agent decides what to do

### For new patches

| Situation | Agent action |
|-----------|-------------|
| New patch, no known bugs | Assesses risk via LLM then installs if Low or Medium |
| New patch, bugs found | Runs root cause analysis then attempts automated fix |
| Root cause fixed successfully | Proceeds to download and install the patch |
| Root cause fix failed | Skips download and gives user detailed manual instructions |
| Patch rated High risk | Holds patch and reports to user |

### For installed patches (historical audit)

| Situation | Agent action |
|-----------|-------------|
| Installed patch, no issues | Marked clean — no action |
| Installed patch, bug found | Runs root cause analysis then attempts automated fix |
| Fix succeeded | Patch retained — bug resolved |
| Fix failed after 3 attempts | Automatically uninstalls the patch with restore point |
| Uninstall also fails | Reports to user with full manual instructions |

### For system errors in event log

| Situation | Agent action |
|-----------|-------------|
| Known error (in cache) | Uses cached fix instantly — no LLM call |
| New error never seen before | LLM diagnoses — result saved to cache permanently |
| File corruption, integrity error | Runs DISM CheckHealth automatically |
| Service failure | Restarts the service automatically |
| Primary fix fails | Tries fallback tool automatically |
| All automated attempts fail | Escalates to user with full context |
| Hardware, BIOS, firmware issue | Always escalates to user — never attempted automatically |

---

## The agent only asks for human help when

- The issue involves hardware failure, BIOS, or firmware
- The issue requires physical access to the machine
- All automated fix attempts have failed and no fallback worked
- A patch is rated High risk and needs a human decision

Everything else is handled automatically.

---

## Report sections

Every cycle generates one combined HTML report covering:

- Summary stats dashboard
- All Windows patches currently installed on the machine
- Windows Update failed history with error codes and failure reasons
- Windows Update success history (last 20)
- All patches successfully installed by the agent across all cycles
- All patches the agent tried to install but failed across all cycles
- New patches detected this cycle with risk assessment
- Historical patch audit results
- System errors found this cycle
- Fixes applied this cycle — showing whether each fix came from cache or LLM

---

## Architecture

```
main.py                  — Entry point and scheduler
agent/
  orchestrator.py        — Coordinates all agent steps in sequence
  llm.py                 — Handles all OLLAMA communication and reasoning
tools/
  patch_tools.py         — Patch detection, download, install, reports
  system_tools.py        — Event log, DISM, restore points, uninstall
database/
  db.py                  — All SQLite operations including error cache
config/
  settings.py            — Centralised settings loaded from .env
reports/                 — Combined HTML reports generated after every cycle
logs/                    — Full agent activity log
```

---

## Agent cycle (what runs every 6 hours)

```
1. Historical audit
   Check all installed patches for newly discovered bugs
   Root cause analysis on any flagged patch
   Attempt automated fix
   Uninstall patch if fix fails

2. Patch detection
   Check Windows Update for new patches
   Fetch known issues for each patch
   If bugs found — root cause analysis — attempt fix first
   Only proceed to download after root cause is resolved

3. Risk assessment
   LLM scores each patch: Low / Medium / High
   Low and Medium — install automatically
   High — hold and report to user

4. Post-install monitoring
   Read Windows Event Log for 24 hours
   Filter for errors and critical events

5. Remediation
   Check error cache first — instant fix if known error
   LLM diagnoses new errors — saves result to cache permanently
   Agent applies fix automatically
   Retry up to 3 times with fallback tool
   Escalate to user only if all attempts fail

6. Combined report
   Single HTML file covering all of the above
   Shows cache vs LLM diagnosis source for every fix
```

---

## Tech stack

| Component | Technology |
|-----------|-----------|
| Local LLM inference | OLLAMA |
| LLM model | Phi-3 Mini 3.8B (fully offline) |
| Agent orchestration | Python 3.10 |
| Scheduling | APScheduler |
| Windows system access | pywin32, PowerShell, WMI |
| Patch operations | Windows Update Agent COM API |
| System repair | DISM, wusa.exe |
| Error cache | SQLite (permanent, never expires) |
| Local database | SQLite |
| Reports | HTML |

---

## Project structure

```
PatchAgent/
├── main.py
├── .env
├── README.md
├── .gitignore
├── agent/
│   ├── __init__.py
│   ├── orchestrator.py
│   └── llm.py
├── config/
│   ├── __init__.py
│   └── settings.py
├── tools/
│   ├── __init__.py
│   ├── patch_tools.py
│   └── system_tools.py
├── database/
│   ├── __init__.py
│   └── db.py
├── reports/
└── logs/
```

---

## Setup and installation

### Requirements
- Windows 10 or Windows 11
- Python 3.10+
- OLLAMA installed and running
- Administrator privileges (required for patch install, DISM, restore points)

### Step 1 — Install OLLAMA
Download from https://ollama.com and install.

Then pull the model:
```bash
ollama pull phi3:mini
```

### Step 2 — Clone the repository
```bash
git clone https://github.com/yourusername/PatchAgent.git
cd PatchAgent
```

### Step 3 — Create virtual environment
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 4 — Install dependencies
```bash
pip install requests apscheduler sqlite-utils python-dotenv colorlog pywin32
```

### Step 5 — Configure environment
Create a `.env` file in the root folder:
```env
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=phi3:mini
AGENT_INTERVAL_HOURS=6
MONITORING_WINDOW_HOURS=24
MAX_REMEDIATION_ATTEMPTS=3
LOG_LEVEL=INFO
```

### Step 6 — Run as administrator
Open PowerShell as administrator and launch VS Code from there:
```bash
cd C:\Users\YourName\PatchAgent
code .
```

Then in the VS Code terminal:
```bash
.\venv\Scripts\Activate.ps1
python main.py
```

---

## Safety guarantees

- A system restore point is created before every patch installation
- A system restore point is created before every patch uninstall
- A system restore point is created before every risky automated fix
- High risk patches are never installed automatically
- Hardware-level issues are never attempted automatically
- Every single agent decision is logged with full reasoning to the database
- Cached fixes that fail 3 times are automatically invalidated and re-diagnosed

---

## Why fully local

- No sensitive system data sent to external APIs
- Works without internet after initial model download
- No subscription cost or API rate limits
- Full control over the model and its behavior
- All logs, reports, and data stay on your machine

---

## Built with

- [OLLAMA](https://ollama.com) — local LLM inference
- [Phi-3 Mini](https://huggingface.co/microsoft/Phi-3-mini-4k-instruct) — Microsoft's lightweight reasoning model
- [APScheduler](https://apscheduler.readthedocs.io) — task scheduling
- [pywin32](https://github.com/mhammond/pywin32) — Windows system access