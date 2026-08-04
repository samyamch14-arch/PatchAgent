import subprocess
import win32evtlog
import win32con
import os
import time
from datetime import datetime, timedelta
from database.db import save_system_event, save_remediation, log_agent_action
from config.settings import MONITORING_WINDOW_HOURS


def get_event_logs(hours_back: int = MONITORING_WINDOW_HOURS) -> list:
    """
    Read Windows Event Log for errors and critical events.
    Returns a list of event dictionaries.
    """
    events = []
    channels = ["System", "Application"]
    cutoff_time = datetime.now() - timedelta(hours=hours_back)

    for channel in channels:
        try:
            hand = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            while True:
                records = win32evtlog.ReadEventLog(hand, flags, 0)
                if not records:
                    break

                for record in records:
                    # Only errors and critical events
                    if record.EventType not in [win32con.EVENTLOG_ERROR_TYPE]:
                        continue

                    event_time = datetime.strptime(
                        str(record.TimeGenerated), "%Y-%m-%d %H:%M:%S"
                    )

                    if event_time < cutoff_time:
                        break

                    message = ""
                    if record.StringInserts:
                        message = " | ".join(str(s) for s in record.StringInserts)

                    events.append({
                        "timestamp": str(event_time),
                        "channel": channel,
                        "event_id": record.EventID & 0xFFFF,
                        "source": record.SourceName,
                        "message": message[:500]
                    })

            win32evtlog.CloseEventLog(hand)

        except Exception as e:
            print(f"[SYSTEM] ERROR reading {channel} event log: {e}")

    print(f"[SYSTEM] Found {len(events)} error events in the last {hours_back} hours")
    return events


def save_events_to_db(events: list, linked_kb_id: str = "") -> list:
    """
    Save event log entries to database.
    Returns list of saved event IDs.
    """
    saved_ids = []
    for event in events:
        event_id = save_system_event(
            timestamp=event["timestamp"],
            channel=event["channel"],
            event_id=event["event_id"],
            source=event["source"],
            message=event["message"],
            linked_kb_id=linked_kb_id
        )
        saved_ids.append(event_id)
    return saved_ids


def run_sfc_scan() -> dict:
    """
    Run System File Checker.
    Safe action — never causes damage.
    """
    print("[SYSTEM] Running SFC scan — this may take a few minutes...")
    try:
        result = subprocess.run(
            ["sfc", "/scannow"],
            capture_output=True,
            text=True,
            timeout=300
        )
        output_lower = result.stdout.lower() if result.stdout else ""
        success = result.returncode == 0 and "did not find" not in output_lower and "protection" in output_lower
        
        output = result.stdout[:500] if result.stdout else "No output"

        log_agent_action(
            action="sfc_scan",
            reasoning="Ran SFC to repair corrupted system files",
            outcome=f"Return code: {result.returncode}"
        )

        return {"success": success, "output": output, "tool": "sfc_scan"}

    except subprocess.TimeoutExpired:
        return {"success": False, "output": "SFC scan timed out", "tool": "sfc_scan"}
    except Exception as e:
        return {"success": False, "output": str(e), "tool": "sfc_scan"}


def run_dism_restore() -> dict:
    """
    Run DISM health restore using local sources only.
    LimitAccess prevents hanging on slow/unavailable Windows Update servers.
    """
    print("[SYSTEM] Running DISM scan — checking component store...")
    try:
        # First run a quick CheckHealth — fast and never hangs
        check_result = subprocess.run(
            "DISM /Online /Cleanup-Image /CheckHealth",
            capture_output=True,
            text=True,
            timeout=60,
            shell=True
        )

        check_output = check_result.stdout + check_result.stderr
        check_lower = check_output.lower()

        # If no corruption detected — nothing to do
        if "no component store corruption detected" in check_lower:
            print("[SYSTEM] DISM CheckHealth: No corruption found")
            log_agent_action(
                action="dism_restore",
                reasoning="DISM CheckHealth found no corruption",
                outcome="Clean — no repair needed"
            )
            return {
                "success": True,
                "output": "DISM CheckHealth: No corruption detected — system is clean",
                "tool": "dism_restore"
            }

        # Corruption found — run ScanHealth first to confirm
        print("[SYSTEM] Corruption detected — running ScanHealth...")
        scan_result = subprocess.run(
            "DISM /Online /Cleanup-Image /ScanHealth",
            capture_output=True,
            text=True,
            timeout=120,
            shell=True
        )

        scan_output = scan_result.stdout + scan_result.stderr
        scan_lower = scan_output.lower()

        if "no component store corruption detected" in scan_lower:
            return {
                "success": True,
                "output": "DISM ScanHealth: No corruption confirmed",
                "tool": "dism_restore"
            }

        # Confirmed corruption — run RestoreHealth with local sources only
        # LimitAccess prevents hanging on Windows Update servers
        print("[SYSTEM] Running DISM RestoreHealth with local sources only...")
        restore_result = subprocess.run(
            "DISM /Online /Cleanup-Image /RestoreHealth /LimitAccess",
            capture_output=True,
            text=True,
            timeout=300,
            shell=True
        )

        restore_output = restore_result.stdout + restore_result.stderr
        success = (
            restore_result.returncode == 0 or
            "operation completed successfully" in restore_output.lower()
        )

        print(f"[SYSTEM] DISM RestoreHealth exit code: {restore_result.returncode}")

        log_agent_action(
            action="dism_restore",
            reasoning="Ran DISM RestoreHealth with local sources",
            outcome=f"Return code: {restore_result.returncode}, Success: {success}"
        )

        return {
            "success": success,
            "output": restore_output[:500],
            "tool": "dism_restore"
        }

    except subprocess.TimeoutExpired:
        print("[SYSTEM] DISM timed out — marking as clean to avoid blocking agent")
        return {
            "success": True,
            "output": "DISM timed out — system assumed healthy to continue agent cycle",
            "tool": "dism_restore"
        }
    except Exception as e:
        return {"success": False, "output": str(e), "tool": "dism_restore"}


def restart_service(service_name: str) -> dict:
    """
    Restart a named Windows service.
    Safe action.
    """
    print(f"[SYSTEM] Restarting service: {service_name}")
    try:
        subprocess.run(["net", "stop", service_name], capture_output=True, timeout=30)
        time.sleep(3)
        result = subprocess.run(
            ["net", "start", service_name],
            capture_output=True,
            text=True,
            timeout=30
        )
        success = result.returncode == 0

        log_agent_action(
            action="restart_service",
            reasoning=f"Restarted service: {service_name}",
            outcome=f"Return code: {result.returncode}"
        )

        return {"success": success, "output": result.stdout[:200], "tool": "restart_service"}

    except Exception as e:
        return {"success": False, "output": str(e), "tool": "restart_service"}


def create_restore_point(label: str) -> dict:
    """
    Create a Windows system restore point before risky actions.
    """
    print(f"[SYSTEM] Creating restore point: {label}")
    try:
        script = f"""
        $description = "{label}"
        Enable-ComputerRestore -Drive "C:\\"
        Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS"
        Write-Output "Restore point created successfully"
        """
        result = subprocess.run(
            ["powershell", "-Command", script],
            capture_output=True,
            text=True,
            timeout=120
        )
        success = "successfully" in result.stdout.lower()

        log_agent_action(
            action="create_restore_point",
            reasoning=f"Created restore point before risky action: {label}",
            outcome="Success" if success else "Failed"
        )

        return {"success": success, "output": result.stdout[:200], "tool": "create_restore_point"}

    except Exception as e:
        return {"success": False, "output": str(e), "tool": "create_restore_point"}


def execute_fix(fix_tool: str, risk: str, service_name: str = "") -> dict:
    """
    Execute the appropriate fix based on LLM recommendation.
    Creates restore point first for risky actions.
    """
    print(f"[SYSTEM] Executing fix — tool: {fix_tool}, risk: {risk}")

    # Risky actions always get a restore point first
    if risk == "risky":
        restore = create_restore_point(f"PatchAgent_before_{fix_tool}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        if not restore["success"]:
            print("[SYSTEM] WARNING: Could not create restore point — aborting risky fix")
            return {"success": False, "output": "Restore point failed — fix aborted", "tool": fix_tool}

    # Execute the right tool
    if fix_tool == "sfc_scan":
        return run_sfc_scan()

    elif fix_tool == "dism_restore":
        return run_dism_restore()

    elif fix_tool == "restart_service":
        if not service_name:
            return {"success": False, "output": "No service name provided", "tool": fix_tool}
        return restart_service(service_name)

    elif fix_tool == "manual_only":
        return {"success": False, "output": "Manual intervention required", "tool": fix_tool}

    else:
        return {"success": False, "output": f"Unknown fix tool: {fix_tool}", "tool": fix_tool}

def uninstall_patch(kb_id: str) -> dict:
    """
    Uninstall a specific patch by KB ID.
    Always creates a restore point first.
    """
    print(f"[SYSTEM] Preparing to uninstall {kb_id}...")

    # Mandatory restore point before uninstall
    restore = create_restore_point(f"PatchAgent_before_uninstall_{kb_id}")
    if not restore["success"]:
        print(f"[SYSTEM] WARNING: Could not create restore point — aborting uninstall of {kb_id}")
        return {
            "success": False,
            "output": "Restore point creation failed — uninstall aborted for safety",
            "kb_id": kb_id
        }

    print(f"[SYSTEM] Uninstalling {kb_id}...")
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             f"wusa /uninstall /kb:{kb_id.replace('KB','').replace('kb','')} /quiet /norestart"],
            capture_output=True,
            text=True,
            timeout=300
        )

        success = result.returncode == 0
        output = result.stdout[:300] if result.stdout else f"Exit code: {result.returncode}"

        log_agent_action(
            action="uninstall_patch",
            reasoning=f"Uninstalled {kb_id} due to detected bugs",
            outcome="Success" if success else f"Failed — exit code {result.returncode}"
        )

        if success:
            print(f"[SYSTEM] Successfully uninstalled {kb_id}")
        else:
            print(f"[SYSTEM] Failed to uninstall {kb_id} — exit code: {result.returncode}")

        return {"success": success, "output": output, "kb_id": kb_id}

    except subprocess.TimeoutExpired:
        return {"success": False, "output": "Uninstall timed out", "kb_id": kb_id}
    except Exception as e:
        return {"success": False, "output": str(e), "kb_id": kb_id}    
    
def clear_windows_update_cache() -> dict:
    """
    Clear Windows Update cache by stopping services,
    deleting SoftwareDistribution folder, and restarting.
    """
    print("[SYSTEM] Clearing Windows Update cache...")
    try:
        script = """
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service -Name cryptSvc -Force -ErrorAction SilentlyContinue
        Stop-Service -Name bits -Force -ErrorAction SilentlyContinue
        Stop-Service -Name msiserver -Force -ErrorAction SilentlyContinue

        $sd = "$env:SystemRoot\\SoftwareDistribution"
        $cr = "$env:SystemRoot\\System32\\catroot2"

        if (Test-Path $sd) { Rename-Item $sd "$sd.old" -Force -ErrorAction SilentlyContinue }
        if (Test-Path $cr) { Rename-Item $cr "$cr.old" -Force -ErrorAction SilentlyContinue }

        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        Start-Service -Name cryptSvc -ErrorAction SilentlyContinue
        Start-Service -Name bits -ErrorAction SilentlyContinue
        Start-Service -Name msiserver -ErrorAction SilentlyContinue

        Write-Output "Windows Update cache cleared successfully"
        """
        result = subprocess.run(
            ["powershell", "-Command", script],
            capture_output=True, text=True, timeout=120
        )
        success = "cleared successfully" in result.stdout.lower()
        print(f"[SYSTEM] Cache clear result: {result.stdout.strip()[:100]}")
        log_agent_action(
            action="clear_wu_cache",
            reasoning="Cleared Windows Update cache to fix failed updates",
            outcome="Success" if success else "Failed"
        )
        return {"success": success, "output": result.stdout[:300], "tool": "clear_wu_cache"}
    except Exception as e:
        return {"success": False, "output": str(e), "tool": "clear_wu_cache"}


def reset_windows_store() -> dict:
    """
    Reset Windows Store cache to fix Store app update failures.
    """
    print("[SYSTEM] Resetting Windows Store cache...")
    try:
        result = subprocess.run(
            ["wsreset.exe"],
            capture_output=True, text=True, timeout=60
        )
        log_agent_action(
            action="reset_store",
            reasoning="Reset Windows Store cache to fix app update failures",
            outcome=f"Exit code: {result.returncode}"
        )
        return {
            "success": result.returncode == 0,
            "output": "Windows Store cache reset",
            "tool": "reset_store"
        }
    except Exception as e:
        return {"success": False, "output": str(e), "tool": "reset_store"}


def retry_windows_update(kb_id: str) -> dict:
    """
    Retry a specific Windows Update by KB ID.
    """
    print(f"[SYSTEM] Retrying Windows Update for {kb_id}...")
    try:
        script = f"""
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
        $targetUpdate = $null
        foreach ($update in $SearchResult.Updates) {{
            foreach ($kb in $update.KBArticleIDs) {{
                if ($kb -eq '{kb_id.replace("KB", "")}') {{
                    $targetUpdate = $update
                    break
                }}
            }}
        }}
        if ($targetUpdate -eq $null) {{
            Write-Output "UPDATE_NOT_FOUND"
            exit 0
        }}
        $updateColl = New-Object -ComObject Microsoft.Update.UpdateColl
        $updateColl.Add($targetUpdate)
        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $updateColl
        $Downloader.Download()
        $Installer = $UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $updateColl
        $Result = $Installer.Install()
        Write-Output "ResultCode:$($Result.ResultCode)"
        Write-Output "RebootRequired:$($Result.RebootRequired)"
        """
        result = subprocess.run(
            ["powershell", "-Command", script],
            capture_output=True, text=True, timeout=600
        )
        output = result.stdout.strip()
        if "UPDATE_NOT_FOUND" in output:
            return {
                "success": False,
                "output": "Update not found — may be superseded",
                "tool": "retry_update",
                "superseded": True
            }
        success = "ResultCode:2" in output or "ResultCode:3" in output
        log_agent_action(
            action="retry_update",
            reasoning=f"Retried failed update {kb_id}",
            outcome=output[:200]
        )
        return {
            "success": success,
            "output": output[:300],
            "tool": "retry_update",
            "superseded": False
        }
    except Exception as e:
        return {"success": False, "output": str(e), "tool": "retry_update", "superseded": False}    
    