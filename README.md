# Autonomous Patch Management Agent

A fully local, AI-powered Windows patch management agent built with Python and OLLAMA.
The agent autonomously detects, assesses, installs, monitors, diagnoses, and fixes
Microsoft Windows patches — with zero human intervention for everything the system
can handle safely.

---

## What it does

- Detects new Microsoft Windows patches automatically every 6 hours
- Checks every new patch for known bugs before downloading
- Performs root cause analysis and attempts to fix the issue before downloading a buggy patch
- Only downloads and installs the patch after the root cause is resolved
- Classifies every buggy patch before acting — security patches, superseded patches, and high-risk bugs are handled differently
- Never uninstalls a security patch regardless of bugs found
- Skips patches already resolved by a newer installed patch — no unnecessary action
- Uses a local LLM (Phi-3 Mini via OLLAMA) to assess patch risk before installing
- Installs Low and Medium risk patches autonomously with restore points
- Monitors Windows Event Log for errors after every patch install
- Uses a permanent error cache — known errors fixed instantly without calling the LLM
- Only calls the LLM for brand new errors it has never seen before
- Remediates recent failed Windows Update history (last 90 days) — clears cache, retries installs
- Resets Windows Store cache for Store app update failures
- Audits all historically installed patches for newly discovered bugs
- Generates a single combined HTML report after every cycle covering everything
- Runs entirely offline — no cloud, no API keys, no data leaves your machine

---

## Smart patch classification

Before the agent acts on any buggy patch it classifies it into one of four categories:

| Classification | Condition | Action |
|---|---|---|
| Skip silently | A newer installed patch already resolves this bug | Do nothing — bug already fixed |
| Safe fix only | Security patch, CVE, Defender update | DISM or service restart only — never uninstall |
| Report only | Bug causes major system impact (BSOD, boot failure) | Log for user — too risky to touch automatically |
| Full remediation | Non-security, non-superseded, low-risk bug | Fix → retry → uninstall as last resort |

---

## How the agent decides what to do

### For new patches

| Situation | Agent action |
|---|---|
| New patch, no known bugs | Assesses risk via LLM then installs if Low or Medium |
| New patch, bugs found | Root cause analysis → automated fix → only downloads after fix succeeds |
| Root cause fix failed | Skips download — detailed manual instructions in report |
| Patch rated High risk | Holds patch and reports to user |

### For installed patches (historical audit)

| Situation | Agent action |
|---|---|
| Clean patch | No action |
| Bug found, newer patch resolves it | Skip silently — already fixed |
| Bug found, security patch | Safe fixes only — DISM, service restart — never uninstall |
| Bug found, major impact | Report only — agent does not touch it |
| Bug found, non-security resolvable | Fix → retry → uninstall with restore point as last resort |

### For failed Windows Update history (last 90 days)

| Error code | Agent action |
|---|---|
| 0x80240016 / 0x80240022 | Already installed or superseded — skip safely |
| 0x80240034 | Restore point → clear SoftwareDistribution cache → retry install |
| Store app failure (N/A) | Reset Windows Store cache |
| Unknown error | Log with manual instructions |

### For system errors in Event Log

| Situation | Agent action |
|---|---|
| Known error (in cache) | Instant fix — zero LLM call |
| New error never seen | LLM diagnoses — saved to cache permanently |
| File corruption or integrity error | DISM CheckHealth → ScanHealth → RestoreHealth |
| Service failure | Restart the service automatically |
| Cached fix fails 3 times | Cache entry deleted — LLM re-diagnoses |
| Hardware, BIOS, firmware | Always escalates to user — never attempted automatically |

---

## The agent only asks for human help when

- A patch is rated High risk
- A bug causes major system impact and cannot be safely touched
- The issue is hardware, BIOS, or firmware level
- All automated fix attempts and fallbacks have failed

Everything else is handled automatically.

---

## Performance

| Scenario | Cycle time |
|---|---|
| All errors known (cache hits) | Under 60 seconds |
| Mix of cached and new errors | 2 to 5 minutes |
| All new errors (first run) | 5 to 15 minutes |
| DISM repair needed | 10 to 30 minutes |

---

## How the error cache works

```
Error comes in
      ↓
Check local cache first (instant)
      ↓
Cache hit? → Use saved fix — zero LLM time
      ↓
No cache entry? → Send to LLM → Save result permanently
      ↓
Same error next cycle → Cache hit — no LLM call ever again
      ↓
If cached fix fails 3 times → Cache deleted → LLM re-diagnoses
```

The cache never expires unless the fix stops working.

---

## Architecture

```
main.py                  — Entry point and scheduler
agent/
  orchestrator.py        — All 7 phases coordinated in sequence
  llm.py                 — OLLAMA communication, cache fingerprinting, root cause analysis
tools/
  patch_tools.py         — Patch detection, classification, install, Windows Update history, reports
  system_tools.py        — Event log, DISM, restore points, uninstall, cache clear, store reset
database/
  db.py                  — SQLite with error cache, patch history, agent audit trail
config/
  settings.py            — All settings loaded from .env
reports/                 — Combined HTML reports generated after every cycle
logs/                    — Full agent activity log
```

---

## Agent cycle (7 phases every 6 hours)

```
Phase 1 — Historical audit
  Check all installed patches for newly discovered bugs
  Classify each buggy patch (superseded / security / major / normal)
  Apply appropriate action per classification

Phase 2 — Failed update remediation (last 90 days)
  Scan Windows Update history for recent failures
  Deduplicate by KB ID
  Clear cache and retry for deployment crashes
  Reset Store cache for app failures
  Skip superseded entries safely

Phase 3 — New patch detection
  Query Windows Update for pending patches
  Fetch known issues from Microsoft API
  Root cause analysis if bugs found
  Fix root cause before downloading

Phase 4 — Risk assessment and installation
  LLM scores each patch Low / Medium / High
  Low and Medium — restore point then install
  High — hold and report

Phase 5 — Post-install monitoring
  Read Windows Event Log for 24 hours
  Filter errors and critical events

Phase 6 — Automated remediation
  Check error cache first
  LLM diagnoses new errors — saves to cache permanently
  DISM / service restart / registry fix
  Retry up to 3 times with fallback tool
  Escalate only if all attempts fail

Phase 7 — Combined report
  Single HTML file covering all phases
  Cache hit statistics shown per fix
```

---

## Report sections

Every cycle generates one combined HTML report:

- Summary dashboard with 7 key stats
- All Windows patches currently installed on the machine
- Failed update remediation results (last 90 days) with actions taken
- Windows Update full failed history with error codes and human-readable failure reasons
- Windows Update success history (last 20)
- All patches ever installed by the agent across all cycles
- All patches the agent ever failed to install
- New patches detected this cycle with risk assessment
- Historical patch audit with classification and action taken
- System errors found this cycle
- Fixes applied — showing whether each fix came from cache or LLM

---

## Tech stack

| Component | Technology |
|---|---|
| Local LLM inference | OLLAMA |
| LLM model | Phi-3 Mini 3.8B (fully offline) |
| Agent orchestration | Python 3.10 |
| Scheduling | APScheduler |
| Windows system access | pywin32, PowerShell, WMI |
| Patch operations | Windows Update Agent COM API |
| System repair | DISM, wusa.exe, wsreset.exe |
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
├── run_agent.bat
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
- Administrator privileges

### Step 1 — Install OLLAMA
Download from https://ollama.com and install.

Then pull the model:
```bash
ollama pull phi3:mini
```

### Step 2 — Clone the repository
```bash
git clone https://github.com/samyamch14-arch/PatchAgent.git
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
Open PowerShell as administrator, then:
```bash
cd PatchAgent
.\venv\Scripts\Activate.ps1
python main.py
```

Or simply double-click `run_agent.bat` — it requests elevation automatically.

---

## Safety guarantees

- Restore point created before every patch installation
- Restore point created before every patch uninstall
- Restore point created before every risky automated fix
- Restore point created before retrying any failed update
- Security patches never uninstalled regardless of bugs
- Superseded bugs never actioned — newer patch already resolved them
- High risk patches never installed automatically
- Major impact bugs never touched automatically
- Hardware-level issues never attempted automatically
- Every agent decision logged with full reasoning to the database
- Cached fixes that fail 3 times automatically invalidated and re-diagnosed

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