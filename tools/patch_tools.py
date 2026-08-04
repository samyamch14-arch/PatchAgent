import subprocess
import requests
import hashlib
import os
import re
import json
from datetime import datetime
from database.db import save_patch, log_agent_action
from config.settings import REPORTS_DIR


def get_installed_patches() -> list:
    print("[PATCH] Fetching installed patches...")
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"[PATCH] ERROR fetching patches: {result.stderr}")
            return []
        patches = json.loads(result.stdout)
        if isinstance(patches, dict):
            patches = [patches]
        print(f"[PATCH] Found {len(patches)} installed patches")
        return patches
    except Exception as e:
        print(f"[PATCH] ERROR: {e}")
        return []


def get_pending_updates() -> list:
    print("[PATCH] Checking for pending Windows updates...")
    try:
        script = """
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
        $updates = @()
        foreach ($update in $SearchResult.Updates) {
            $kbIds = @($update.KBArticleIDs) -join ','
            $updates += @{
                Title = $update.Title
                KBArticleIDs = $kbIds
                Description = $update.Description
                MsrcSeverity = $update.MsrcSeverity
                IsDownloaded = $update.IsDownloaded
            }
        }
        $updates | ConvertTo-Json
        """
        result = subprocess.run(
            ["powershell", "-Command", script],
            capture_output=True, text=True, timeout=300
        )
        if not result.stdout.strip():
            print("[PATCH] No pending updates found")
            return []
        updates = json.loads(result.stdout)
        if isinstance(updates, dict):
            updates = [updates]
        print(f"[PATCH] Found {len(updates)} pending updates")
        return updates
    except Exception as e:
        print(f"[PATCH] ERROR checking pending updates: {e}")
        return []


def get_known_issues(kb_id: str) -> str:
    print(f"[PATCH] Checking known issues for {kb_id}...")
    try:
        kb_number = kb_id.replace("KB", "").replace("kb", "").strip()
        url = f"https://support.microsoft.com/api/content/kb/{kb_number}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            known_issues = data.get("knownIssues", "")
            if known_issues:
                return str(known_issues)[:500]
        return "No known issues found in Microsoft database."
    except Exception as e:
        print(f"[PATCH] Could not fetch known issues for {kb_id}: {e}")
        return "Could not retrieve known issues — network error or patch not found."


def download_patch(kb_id: str, download_url: str) -> dict:
    print(f"[PATCH] Downloading patch {kb_id}...")
    download_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "downloads")
    os.makedirs(download_dir, exist_ok=True)
    file_path = os.path.join(download_dir, f"{kb_id}.msu")
    try:
        response = requests.get(download_url, stream=True, timeout=300)
        response.raise_for_status()
        with open(file_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        print(f"[PATCH] Download complete. SHA256: {file_hash[:16]}...")
        log_agent_action(
            action="download_patch",
            reasoning=f"Downloaded patch {kb_id}",
            outcome=f"File saved to {file_path}"
        )
        return {"success": True, "file_path": file_path, "sha256": file_hash}
    except Exception as e:
        print(f"[PATCH] ERROR downloading {kb_id}: {e}")
        return {"success": False, "file_path": "", "sha256": ""}


def install_patch_from_file(kb_id: str, file_path: str) -> dict:
    print(f"[PATCH] Installing patch {kb_id} from {file_path}...")
    start_time = datetime.now()
    try:
        result = subprocess.run(
            ["wusa.exe", file_path, "/quiet", "/norestart"],
            capture_output=True, text=True, timeout=600
        )
        end_time = datetime.now()
        duration = (end_time - start_time).seconds
        success = result.returncode == 0
        print(f"[PATCH] Install complete in {duration}s — exit code: {result.returncode}")
        log_agent_action(
            action="install_patch",
            reasoning=f"Installed patch {kb_id}",
            outcome=f"Exit code: {result.returncode}, Duration: {duration}s"
        )
        return {"success": success, "exit_code": result.returncode, "duration_seconds": duration, "kb_id": kb_id}
    except subprocess.TimeoutExpired:
        return {"success": False, "exit_code": -1, "duration_seconds": 600, "kb_id": kb_id}
    except Exception as e:
        return {"success": False, "exit_code": -1, "duration_seconds": 0, "kb_id": kb_id}


def install_pending_updates() -> dict:
    print("[PATCH] Installing pending updates via Windows Update...")
    try:
        script = """
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
        if ($SearchResult.Updates.Count -eq 0) {
            Write-Output "NO_UPDATES"
            exit 0
        }
        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $SearchResult.Updates
        $Downloader.Download()
        $Installer = $UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $SearchResult.Updates
        $InstallResult = $Installer.Install()
        Write-Output "ResultCode:$($InstallResult.ResultCode)"
        Write-Output "RebootRequired:$($InstallResult.RebootRequired)"
        """
        result = subprocess.run(
            ["powershell", "-Command", script],
            capture_output=True, text=True, timeout=1800
        )
        output = result.stdout.strip()
        success = "ResultCode:2" in output or "ResultCode:3" in output
        log_agent_action(
            action="install_pending_updates",
            reasoning="Installed all pending Windows updates",
            outcome=output[:200]
        )
        return {
            "success": success,
            "output": output,
            "reboot_required": "RebootRequired:True" in output
        }
    except Exception as e:
        print(f"[PATCH] ERROR installing updates: {e}")
        return {"success": False, "output": str(e), "reboot_required": False}


def get_installed_patch_registry() -> list:
    print("[AUDIT] Fetching full installed patch registry...")
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy | ConvertTo-Json"],
            capture_output=True, text=True, timeout=60
        )
        if not result.stdout.strip():
            print("[AUDIT] No installed patches found")
            return []
        patches = json.loads(result.stdout)
        if isinstance(patches, dict):
            patches = [patches]
        cleaned = []
        for p in patches:
            kb_id = str(p.get("HotFixID", "")).strip()
            if kb_id and not kb_id.upper().startswith("KB"):
                kb_id = f"KB{kb_id}"
            cleaned.append({
                "kb_id": kb_id,
                "description": p.get("Description", ""),
                "installed_on": str(p.get("InstalledOn", "")),
                "installed_by": str(p.get("InstalledBy", ""))
            })
        print(f"[AUDIT] Found {len(cleaned)} installed patches")
        return cleaned
    except Exception as e:
        print(f"[AUDIT] ERROR fetching installed patches: {e}")
        return []


def check_patch_against_bug_db(kb_id: str) -> dict:
    print(f"[AUDIT] Checking {kb_id} against bug database...")
    try:
        kb_number = kb_id.replace("KB", "").replace("kb", "").strip()
        url = f"https://support.microsoft.com/api/content/kb/{kb_number}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            known_issues = data.get("knownIssues", "")
            title = data.get("title", "")
            if known_issues:
                return {
                    "kb_id": kb_id,
                    "title": title,
                    "has_issues": True,
                    "issues": str(known_issues)[:500]
                }
        return {"kb_id": kb_id, "title": "", "has_issues": False, "issues": ""}
    except Exception as e:
        return {"kb_id": kb_id, "title": "", "has_issues": False, "issues": f"Could not check: {e}"}


def parse_installed_date(raw) -> str:
    if not raw:
        return "Unknown"
    raw = str(raw)
    if "DateTime" in raw:
        match = re.search(r"DateTime':\s*'(.+?)'", raw)
        if match:
            return match.group(1)
    return raw


def safe_str(val, limit=0) -> str:
    """Convert any value safely to string, optionally truncate."""
    if val is None:
        return ""
    if isinstance(val, list):
        val = ", ".join(str(v) for v in val)
    else:
        val = str(val)
    if limit and len(val) > limit:
        val = val[:limit]
    return val


def get_windows_update_history() -> list:
    print("[PATCH] Fetching Windows Update history...")
    try:
        script = """
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $HistoryCount = $Searcher.GetTotalHistoryCount()
        $History = $Searcher.QueryHistory(0, $HistoryCount)
        $results = @()
        foreach ($entry in $History) {
            $kbArticle = "N/A"
            if ($entry.Title -match 'KB(\\d+)') {
                $kbArticle = "KB" + $matches[1]
            }
            $status = switch ($entry.ResultCode) {
                0 { "Not Started" }
                1 { "In Progress" }
                2 { "Succeeded" }
                3 { "Succeeded With Errors" }
                4 { "Failed" }
                5 { "Aborted" }
                default { "Unknown" }
            }
            $failCode = $entry.HResult
            $failReason = switch ($failCode) {
                0x80240016 { "Update is already installed or superseded" }
                0x80240008 { "Insufficient disk space to install update" }
                0x8024A10A { "Update installation could not be completed — service issue" }
                0x8024A233 { "Update package could not be opened or is corrupt" }
                0x80070005 { "Access denied — insufficient permissions" }
                0x80070490 { "Element not found — update may be invalid" }
                0x8007000E { "Not enough memory to complete the operation" }
                0x80073712 { "Update files are missing or corrupt" }
                0x800705B4 { "Operation timed out" }
                0x80240034 { "Unknown deployment crash — check WindowsUpdate.log" }
                0x80240022 { "All updates are already installed" }
                0x80240020 { "Update not applicable to this system" }
                0xC1900101 { "Driver compatibility issue during update" }
                0x80070003 { "Path not found — system file missing" }
                0x80070002 { "Required file not found" }
                default { if ($entry.UnmappedResultCode -ne 0) { "Unknown error — code 0x{0:X8}" -f $failCode } else { "No additional details recorded" } }
            }
            $results += @{
                Date = $entry.Date.ToString("yyyy-MM-dd HH:mm:ss")
                Title = $entry.Title
                KBArticle = $kbArticle
                Status = $status
                ResultCode = $entry.ResultCode
                ErrorCode = "0x{0:X8}" -f $entry.HResult
                FailureReason = $failReason
            }
        }
        $results | ConvertTo-Json
        """
        result = subprocess.run(
            ["powershell", "-Command", script],
            capture_output=True, text=True, timeout=60
        )
        if not result.stdout.strip():
            print("[PATCH] No Windows Update history found")
            return []
        history = json.loads(result.stdout)
        if isinstance(history, dict):
            history = [history]
        print(f"[PATCH] Found {len(history)} Windows Update history entries")
        return history
    except Exception as e:
        print(f"[PATCH] ERROR fetching update history: {e}")
        return []
    
def classify_patch_safety(kb_id: str, title: str, bug_description: str, installed_patches: list) -> dict:
    """
    Classify a buggy patch before deciding what action to take.
    Returns a classification dict with safe action level.
    """
    title_lower = title.lower()
    bug_lower = bug_description.lower()

    # Check 1 — Is this a security patch?
    security_keywords = [
        "security", "defender", "intelligence update", "antivirus",
        "antimalware", "cumulative update", "critical", "important"
    ]
    is_security = any(kw in title_lower for kw in security_keywords)

    # Check 2 — Is the bug a security vulnerability?
    vulnerability_keywords = [
        "cve-", "vulnerability", "exploit", "remote code execution",
        "privilege escalation", "zero day", "rce", "elevation of privilege"
    ]
    is_vulnerability = any(kw in bug_lower for kw in vulnerability_keywords)

    # Check 3 — Is there a newer patch installed that supersedes this one?
    # Compare KB numbers — higher KB number = newer patch for same component
    kb_number = int(kb_id.replace("KB", "").replace("kb", "")) if kb_id.startswith("KB") else 0
    is_superseded = False
    superseded_by = ""

    # Detect component family from title
    component_keywords = []
    if "windows 11" in title_lower:
        component_keywords.append("windows 11")
    if "windows 10" in title_lower:
        component_keywords.append("windows 10")
    if "defender" in title_lower or "antivirus" in title_lower:
        component_keywords.append("defender")
    if ".net" in title_lower:
        component_keywords.append(".net")
    if "office" in title_lower:
        component_keywords.append("office")

    for installed in installed_patches:
        inst_kb = installed.get("kb_id", "")
        inst_title = installed.get("title", installed.get("description", "")).lower()
        inst_number = int(inst_kb.replace("KB", "").replace("kb", "")) if inst_kb.startswith("KB") else 0

        # Skip if same patch
        if inst_kb == kb_id:
            continue

        # If newer KB from same component family is installed — superseded
        if inst_number > kb_number and component_keywords:
            if any(kw in inst_title for kw in component_keywords):
                is_superseded = True
                superseded_by = inst_kb
                break

    # Check 4 — Does the bug description suggest major system impact?
    major_impact_keywords = [
        "boot failure", "blue screen", "bsod", "system crash",
        "cannot start", "unbootable", "kernel panic", "data loss",
        "corruption", "registry damage", "network failure"
    ]
    is_major_impact = any(kw in bug_lower for kw in major_impact_keywords)

    # Determine action level
    if is_superseded:
        action_level = "skip"
        reason = f"Bug resolved by newer installed patch {superseded_by}"
    elif is_security or is_vulnerability:
        action_level = "safe_fix_only"
        reason = "Security patch — safe fixes only, never uninstall"
    elif is_major_impact:
        action_level = "report_only"
        reason = "Bug causes major system impact — too risky to touch automatically"
    else:
        action_level = "full_remediation"
        reason = "Non-security patch with resolvable bug — full remediation permitted"

    return {
        "kb_id": kb_id,
        "is_security": is_security,
        "is_vulnerability": is_vulnerability,
        "is_superseded": is_superseded,
        "superseded_by": superseded_by,
        "is_major_impact": is_major_impact,
        "action_level": action_level,
        "reason": reason
    }    


def generate_patch_report(patches: list, issues: list, fixes: list, audit_results: list = None, update_history: list = None, failed_update_results: list = None) -> str:
    if audit_results is None:
        audit_results = []
    if update_history is None:
        update_history = []
    if failed_update_results is None:
        failed_update_results = []

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORTS_DIR, f"report_{timestamp}.html")

    from database.db import get_all_installed_by_agent, get_all_failed_by_agent

    agent_installed_history = get_all_installed_by_agent()
    agent_failed_history = get_all_failed_by_agent()

    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy | ConvertTo-Json"],
            capture_output=True, text=True, timeout=60
        )
        if result.stdout.strip():
            system_patches = json.loads(result.stdout)
            if isinstance(system_patches, dict):
                system_patches = [system_patches]
        else:
            system_patches = []
    except Exception:
        system_patches = []

    flagged = [r for r in audit_results if r.get("has_issues")]
    fixed_count = len([f for f in fixes if f.get("success")])

    # ── patch_rows ──
    patch_rows = ""
    for p in patches:
        risk = safe_str(p.get("risk_level", ""))
        status = safe_str(p.get("status", ""))
        reasoning = safe_str(p.get("risk_reasoning", p.get("reasoning", "")), 120)
        status_class = "good" if status == "installed" else "warn" if status == "detected" else "bad"
        patch_rows += (
            "<tr>"
            "<td><strong>" + safe_str(p.get("kb_id", "")) + "</strong></td>"
            "<td>" + safe_str(p.get("title", "")) + "</td>"
            "<td><span class='badge badge-" + risk.lower() + "'>" + risk + "</span></td>"
            "<td>" + reasoning + "</td>"
            "<td class='" + status_class + "'>" + status.capitalize() + "</td>"
            "</tr>"
        )

    # ── system_patch_rows ──
    system_patch_rows = ""
    for p in system_patches:
        system_patch_rows += (
            "<tr>"
            "<td><strong>" + safe_str(p.get("HotFixID", "")) + "</strong></td>"
            "<td>" + safe_str(p.get("Description", "")) + "</td>"
            "<td>" + parse_installed_date(safe_str(p.get("InstalledOn", ""))) + "</td>"
            "<td>" + safe_str(p.get("InstalledBy", "")) + "</td>"
            "</tr>"
        )

    # ── agent_installed_rows ──
    agent_installed_rows = ""
    for p in agent_installed_history:
        agent_installed_rows += (
            "<tr>"
            "<td><strong>" + safe_str(p.get("kb_id", "")) + "</strong></td>"
            "<td>" + safe_str(p.get("title", "")) + "</td>"
            "<td>" + safe_str(p.get("risk_level", "")) + "</td>"
            "<td>" + safe_str(p.get("install_date", p.get("created_at", "")))[:19] + "</td>"
            "<td class='good'>Installed</td>"
            "</tr>"
        )

    # ── agent_failed_rows ──
    agent_failed_rows = ""
    for p in agent_failed_history:
        agent_failed_rows += (
            "<tr>"
            "<td><strong>" + safe_str(p.get("kb_id", "")) + "</strong></td>"
            "<td>" + safe_str(p.get("title", "")) + "</td>"
            "<td>" + safe_str(p.get("risk_level", "")) + "</td>"
            "<td>" + safe_str(p.get("created_at", ""))[:19] + "</td>"
            "<td>" + safe_str(p.get("risk_reasoning", ""), 150) + "</td>"
            "<td class='bad'>Failed</td>"
            "</tr>"
        )

    # ── audit_rows ──
    audit_rows = ""
    for r in audit_results:
        has_issues = r.get("has_issues", False)
        badge_class = "badge-issue" if has_issues else "badge-clean"
        badge_text = "Issues Found" if has_issues else "Clean"
        action = safe_str(r.get("action_taken", "none"))
        root_cause = safe_str(r.get("root_cause", ""))
        manual_instructions = safe_str(r.get("manual_instructions", ""))
        action_level = safe_str(r.get("action_level", ""))

        action_display = "—"
        action_class = ""

        if action == "skipped_superseded":
            action_display = "Skipped — resolved in newer patch"
            action_class = "warn"
        elif action == "reported_only":
            action_display = "Reported only — too risky to touch"
            action_class = "bad"
        elif action == "security_patch_reported":
            action_display = "Security patch — manual review needed"
            action_class = "bad"
        elif action == "security_patch_fix_failed":
            action_display = "Security patch — safe fix failed"
            action_class = "bad"
        elif "safe_fixed" in action:
            action_display = "Safe fix applied — security patch kept"
            action_class = "good"
        elif "fixed" in action:
            action_display = "Fixed automatically"
            action_class = "good"
        elif action == "uninstalled":
            action_display = "Uninstalled safely"
            action_class = "warn"
        elif action == "uninstall_failed":
            action_display = "Uninstall failed — manual needed"
            action_class = "bad"
        elif action == "manual_required":
            action_display = "Manual action required"
            action_class = "bad"

        manual_row = ""
        if manual_instructions and action in [
            "reported_only", "uninstall_failed",
            "security_patch_reported", "security_patch_fix_failed"
        ]:
            manual_row = (
                "<tr style='background:#fff7ed'>"
                "<td colspan='6' style='font-size:12px;color:#92400e;padding:8px 12px'>"
                "<strong>Manual Instructions:</strong> " + manual_instructions[:300] +
                "</td></tr>"
            )

        issues_text = safe_str(r.get("issues", ""), 100) if has_issues else "—"
        audit_rows += (
            "<tr>"
            "<td><strong>" + safe_str(r.get("kb_id", "")) + "</strong></td>"
            "<td>" + safe_str(r.get("description", "")) + "</td>"
            "<td>" + parse_installed_date(safe_str(r.get("installed_on", ""))) + "</td>"
            "<td><span class='badge " + badge_class + "'>" + badge_text + "</span></td>"
            "<td>" + (root_cause[:100] if root_cause else issues_text) + "</td>"
            "<td class='" + action_class + "'>" + action_display + "</td>"
            "</tr>" + manual_row
        )

    # ── issue_rows ──
    issue_rows = ""
    for i in issues:
        issue_rows += (
            "<tr>"
            "<td>" + safe_str(i.get("timestamp", "")) + "</td>"
            "<td>" + safe_str(i.get("channel", "")) + "</td>"
            "<td><strong>" + safe_str(i.get("source", "")) + "</strong></td>"
            "<td>" + safe_str(i.get("event_id", "")) + "</td>"
            "<td>" + safe_str(i.get("message", ""), 150) + "</td>"
            "</tr>"
        )

    # ── fix_rows ──
    fix_rows = ""
    for f in fixes:
        success = f.get("success", False)
        tool = safe_str(f.get("tool", ""))
        diagnosis = safe_str(f.get("diagnosis", ""), 150)
        is_manual = tool == "manual_only"
        from_cache = f.get("from_cache", False)
        source_label = "Cache" if from_cache else "LLM"
        result_text = "Fixed automatically" if success else "Manual required" if is_manual else "Failed — escalated"
        result_class = "good" if success else "warn" if is_manual else "bad"
        fix_rows += (
            "<tr>"
            "<td>" + safe_str(f.get("source", "")) + "</td>"
            "<td>" + tool + "</td>"
            "<td><span class='badge " + ("badge-clean" if from_cache else "badge-medium") + "'>" + source_label + "</span></td>"
            "<td>" + diagnosis + "</td>"
            "<td>" + safe_str(f.get("output", ""), 150) + "</td>"
            "<td class='" + result_class + "'>" + result_text + "</td>"
            "</tr>"
        )
        
    # ── failed remediation rows ──
    failed_remediation_rows = ""
    for r in failed_update_results:
        action = r.get("action_taken", "none")
        success = r.get("success", False)
        if action in ["skipped", "superseded"]:
            action_class = "warn"
            action_text = "Skipped — superseded or already installed"
        elif success:
            action_class = "good"
            action_text = "Fixed automatically"
        elif action == "manual_required" or action == "retry_failed":
            action_class = "bad"
            action_text = "Manual required"
        else:
            action_class = "bad"
            action_text = "Failed"
        failed_remediation_rows += (
            "<tr>"
            "<td>" + safe_str(r.get("kb_id", "")) + "</td>"
            "<td>" + safe_str(r.get("title", ""), 80) + "</td>"
            "<td class='bad'>" + safe_str(r.get("error_code", "")) + "</td>"
            "<td>" + safe_str(r.get("failure_reason", ""), 100) + "</td>"
            "<td class='" + action_class + "'>" + action_text + "</td>"
            "<td>" + safe_str(r.get("action_result", ""), 150) + "</td>"
            "</tr>"
        )    

    # ── history rows ──
    history_failed = [h for h in update_history if h.get("ResultCode") == 4 or h.get("Status") == "Failed"]
    history_succeeded = [h for h in update_history if h.get("ResultCode") == 2 or h.get("Status") == "Succeeded"]

    history_failed_rows = ""
    for h in history_failed:
        history_failed_rows += (
            "<tr>"
            "<td>" + safe_str(h.get("Date", ""))[:19] + "</td>"
            "<td>" + safe_str(h.get("Title", ""), 80) + "</td>"
            "<td><strong>" + safe_str(h.get("KBArticle", "N/A")) + "</strong></td>"
            "<td><span class='badge badge-issue'>Failed</span></td>"
            "<td class='bad'>" + safe_str(h.get("ErrorCode", "")) + "</td>"
            "<td>" + safe_str(h.get("FailureReason", "No details recorded"), 200) + "</td>"
            "</tr>"
        )

    history_succeeded_rows = ""
    for h in history_succeeded[:20]:
        history_succeeded_rows += (
            "<tr>"
            "<td>" + safe_str(h.get("Date", ""))[:19] + "</td>"
            "<td>" + safe_str(h.get("Title", ""), 80) + "</td>"
            "<td><strong>" + safe_str(h.get("KBArticle", "N/A")) + "</strong></td>"
            "<td><span class='badge badge-clean'>Succeeded</span></td>"
            "<td>" + safe_str(h.get("ErrorCode", "0x00000000")) + "</td>"
            "<td>—</td>"
            "</tr>"
        )

    # ── HTML ──
    html = """<html>
<head>
<title>Patch Agent Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:40px auto;color:#1a1a2e}
h1{color:#1e40af;margin-bottom:4px}
h2{color:#374151;border-bottom:2px solid #e5e7eb;padding-bottom:6px;margin-top:40px}
.meta{font-size:13px;color:#6b7280;margin-bottom:32px}
.summary{display:flex;gap:14px;margin-bottom:32px;flex-wrap:wrap}
.stat{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px 20px;text-align:center;min-width:110px}
.stat .num{font-size:30px;font-weight:700}
.stat .label{font-size:11px;color:#6b7280;margin-top:4px}
.num-red{color:#991b1b}.num-green{color:#166534}.num-blue{color:#1e40af}.num-amber{color:#92400e}
table{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:13px}
th{background:#1e40af;color:white;padding:10px 12px;text-align:left}
td{padding:9px 12px;border-bottom:1px solid #e5e7eb}
tr:nth-child(even) td{background:#f8fafc}
.good{color:#166534;font-weight:600}.bad{color:#991b1b;font-weight:600}.warn{color:#92400e;font-weight:600}
.badge{display:inline-block;padding:2px 10px;border-radius:6px;font-size:11px;font-weight:700}
.badge-low{background:#dcfce7;color:#166534}
.badge-medium{background:#fef3c7;color:#92400e}
.badge-high{background:#fee2e2;color:#991b1b}
.badge-clean{background:#dcfce7;color:#166534}
.badge-issue{background:#fee2e2;color:#991b1b}
.empty{color:#166634;font-size:13px;padding:8px 0}
.section-note{font-size:12px;color:#6b7280;margin-bottom:12px}
.section-divider{border:none;border-top:3px solid #1e40af;margin:40px 0}
</style>
</head>
<body>
<h1>Patch Agent — Full Report</h1>
<div class="meta">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """ &nbsp;|&nbsp; Powered by OLLAMA + Phi-3 Mini</div>

<div class="summary">
    <div class="stat"><div class="num num-blue">""" + str(len(system_patches)) + """</div><div class="label">Total patches on machine</div></div>
    <div class="stat"><div class="num num-green">""" + str(len(agent_installed_history)) + """</div><div class="label">Installed by agent (all time)</div></div>
    <div class="stat"><div class="num num-red">""" + str(len(agent_failed_history)) + """</div><div class="label">Failed installs (all time)</div></div>
    <div class="stat"><div class="num num-blue">""" + str(len(audit_results)) + """</div><div class="label">Patches audited</div></div>
    <div class="stat"><div class="num num-red">""" + str(len(flagged)) + """</div><div class="label">Audit issues found</div></div>
    <div class="stat"><div class="num num-red">""" + str(len(issues)) + """</div><div class="label">System errors</div></div>
    <div class="stat"><div class="num num-green">""" + str(fixed_count) + """</div><div class="label">Fixed this cycle</div></div>
</div>

<hr class="section-divider">
<h2>All Windows Patches Currently Installed on This Machine</h2>
<p class="section-note">Complete list of every patch on this machine right now.</p>
""" + (
    "<p class='empty'>No patches found on machine.</p>" if not system_patches else
    "<table><tr><th>KB ID</th><th>Description</th><th>Installed On</th><th>Installed By</th></tr>" +
    system_patch_rows + "</table>"
) + """

<hr class="section-divider">
<h2>Failed Update Remediation (Last 90 Days)</h2>
<p class="section-note">Agent attempted to fix recent Windows Update failures. Superseded patches are safely skipped.</p>
""" + (
    "<p class='empty'>No recent failed updates found in the last 90 days.</p>" if not failed_update_results else
    "<table><tr><th>KB ID</th><th>Title</th><th>Error Code</th><th>Failure Reason</th><th>Result</th><th>Action Taken</th></tr>" +
    failed_remediation_rows + "</table>"
) + """

<hr class="section-divider">
<h2>Windows Update Failed History</h2>
<p class="section-note">All updates that failed to install — including error codes and failure reasons.</p>
""" + (
    "<p class='empty'>No failed updates on record.</p>" if not history_failed else
    "<table><tr><th>Date</th><th>Title</th><th>KB Article</th><th>Status</th><th>Error Code</th><th>Failure Reason</th></tr>" +
    history_failed_rows + "</table>"
) + """

<hr class="section-divider">
<h2>Windows Update Success History (Last 20)</h2>
<p class="section-note">Most recent successfully installed updates on this machine.</p>
""" + (
    "<p class='empty'>No update history found.</p>" if not history_succeeded else
    "<table><tr><th>Date</th><th>Title</th><th>KB Article</th><th>Status</th><th>Error Code</th><th>Notes</th></tr>" +
    history_succeeded_rows + "</table>"
) + """

<hr class="section-divider">
<h2>All Patches Successfully Installed by the Agent (All Time)</h2>
<p class="section-note">Every patch the agent has ever successfully installed across all cycles.</p>
""" + (
    "<p class='empty'>Agent has not successfully installed any patches yet.</p>" if not agent_installed_history else
    "<table><tr><th>KB ID</th><th>Title</th><th>Risk Level</th><th>Installed On</th><th>Status</th></tr>" +
    agent_installed_rows + "</table>"
) + """

<hr class="section-divider">
<h2>All Patches the Agent Tried to Install But Failed (All Time)</h2>
<p class="section-note">Every patch install the agent attempted but could not complete.</p>
""" + (
    "<p class='empty'>No failed installs on record.</p>" if not agent_failed_history else
    "<table><tr><th>KB ID</th><th>Title</th><th>Risk Level</th><th>Attempted On</th><th>Reason</th><th>Status</th></tr>" +
    agent_failed_rows + "</table>"
) + """

<hr class="section-divider">
<h2>This Cycle — New Patches Detected</h2>
<p class="section-note">Patches found and assessed by the agent in this cycle.</p>
""" + (
    "<p class='empty'>No new patches detected this cycle.</p>" if not patches else
    "<table><tr><th>KB ID</th><th>Title</th><th>Risk</th><th>Reasoning</th><th>Status</th></tr>" +
    patch_rows + "</table>"
) + """

<hr class="section-divider">
<h2>Historical Patch Audit</h2>
<p class="section-note">All installed patches checked against Microsoft known issues database.</p>
""" + (
    "<p class='empty'>No audit data available.</p>" if not audit_results else
    "<table><tr><th>KB ID</th><th>Description</th><th>Installed On</th><th>Status</th><th>Root Cause</th><th>Action Taken</th></tr>" +
    audit_rows + "</table>"
) + """

<hr class="section-divider">
<h2>System Errors Found This Cycle</h2>
<p class="section-note">Errors detected in Windows Event Log in the last 24 hours.</p>
""" + (
    "<p class='empty'>No system errors detected.</p>" if not issues else
    "<table><tr><th>Time</th><th>Channel</th><th>Source</th><th>Event ID</th><th>Message</th></tr>" +
    issue_rows + "</table>"
) + """

<hr class="section-divider">
<h2>Fixes Applied This Cycle</h2>
<p class="section-note">Remediation actions taken by the agent. Manual items require your attention.</p>
""" + (
    "<p class='empty'>No fixes required this cycle.</p>" if not fixes else
    "<table><tr><th>Error Source</th><th>Tool Used</th><th>Diagnosed By</th><th>Diagnosis</th><th>Action Taken</th><th>Result</th></tr>" +
    fix_rows + "</table>"
) + """

</body>
</html>"""

    with open(report_path, "w") as f:
        f.write(html)

    print(f"[PATCH] Report written to {report_path}")
    return report_path


def generate_audit_report(audit_results: list) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORTS_DIR, f"audit_{timestamp}.html")
    with open(report_path, "w") as f:
        f.write("<html><body><p>Audit complete — see main report for full details.</p></body></html>")
    return report_path


def generate_audit_report(audit_results: list) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORTS_DIR, f"audit_{timestamp}.html")
    with open(report_path, "w") as f:
        f.write("<html><body><p>Audit complete — see main report for full details.</p></body></html>")
    return report_path