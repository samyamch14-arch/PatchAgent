import threading
import time
import win32evtlog
import win32con
import win32api
import winerror
from datetime import datetime, timedelta
from database.db import (
    get_cached_diagnosis,
    save_cached_diagnosis,
    update_cache_success,
    log_agent_action,
    save_system_event
)
from agent.llm import diagnose_system_error, get_message_fingerprint
from agent.notifier import notify_realtime_fix
from tools.system_tools import execute_fix


class RealTimeEventWatcher:
    """
    Watches Windows Event Log continuously in a background thread.
    Triggers immediate remediation for Critical severity events.
    Only processes each unique error once per 30 minutes to avoid duplicates.
    """

    def __init__(self):
        self._thread = None
        self._stop_event = threading.Event()
        self._recently_handled = {}  # fingerprint -> timestamp
        self._cooldown_minutes = 30
        self._channels = ["System", "Application"]

    def start(self):
        """Start the background watcher thread."""
        if self._thread and self._thread.is_alive():
            print("[WATCHER] Already running")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._watch_loop,
            name="EventLogWatcher",
            daemon=True  # dies automatically when main process exits
        )
        self._thread.start()
        print("[WATCHER] Real-time Event Log watcher started")
        log_agent_action(
            action="watcher_started",
            reasoning="Real-time Critical event watcher running in background"
        )

    def stop(self):
        """Stop the background watcher thread."""
        self._stop_event.set()
        print("[WATCHER] Real-time watcher stopped")

    def _watch_loop(self):
        """Main loop — reads Event Log every 10 seconds for Critical events."""
        handles = {}

        # Open event log handles
        for channel in self._channels:
            try:
                handles[channel] = win32evtlog.OpenEventLog(None, channel)
            except Exception as e:
                print(f"[WATCHER] Could not open {channel} log: {e}")

        print("[WATCHER] Watching for Critical events every 10 seconds...")

        while not self._stop_event.is_set():
            try:
                for channel, handle in handles.items():
                    self._check_channel(channel, handle)
            except Exception as e:
                print(f"[WATCHER] Error in watch loop: {e}")

            # Check every 10 seconds
            self._stop_event.wait(timeout=10)

        # Clean up handles
        for handle in handles.values():
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass

    def _check_channel(self, channel: str, handle):
        """Check a single Event Log channel for new Critical events."""
        try:
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ |
                win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )
            cutoff = datetime.now() - timedelta(minutes=2)

            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                return

            for record in records:
                # Only Critical events
                if record.EventType != win32con.EVENTLOG_ERROR_TYPE:
                    continue

                # Only very recent events (last 2 minutes)
                try:
                    event_time = datetime.strptime(
                        str(record.TimeGenerated), "%Y-%m-%d %H:%M:%S"
                    )
                except Exception:
                    continue

                if event_time < cutoff:
                    break

                message = ""
                if record.StringInserts:
                    message = " | ".join(str(s) for s in record.StringInserts)

                source = record.SourceName
                event_id = record.EventID & 0xFFFF

                # Generate fingerprint
                fingerprint = get_message_fingerprint(source, message)

                # Check cooldown — skip if handled recently
                if self._is_in_cooldown(fingerprint):
                    continue

                print(f"\n[WATCHER] Critical event detected: {source} (ID: {event_id})")
                print(f"[WATCHER] Message: {message[:100]}")

                # Mark as being handled
                self._recently_handled[fingerprint] = datetime.now()

                # Save to database
                save_system_event(
                    timestamp=str(event_time),
                    channel=channel,
                    event_id=event_id,
                    source=source,
                    message=message[:500],
                    linked_kb_id=""
                )

                # Handle in a separate thread so watcher keeps running
                handler_thread = threading.Thread(
                    target=self._handle_event,
                    args=(source, message, fingerprint),
                    daemon=True
                )
                handler_thread.start()

        except Exception as e:
            if "No more data" not in str(e):
                print(f"[WATCHER] Error checking {channel}: {e}")

    def _handle_event(self, source: str, message: str, fingerprint: str):
        """
        Diagnose and fix a Critical event.
        Runs in its own thread so the watcher loop is not blocked.
        """
        print(f"[WATCHER] Handling critical event from {source}...")

        # Check cache first
        cached = get_cached_diagnosis(source, fingerprint)

        if cached:
            fix_tool = cached["fix_tool"]
            risk = cached["risk"]
            diagnosis = cached["diagnosis"]
            print(f"[WATCHER] Cache hit — {diagnosis}")
        else:
            print(f"[WATCHER] New error — sending to LLM...")
            diagnosis_result = diagnose_system_error(message, "")
            fix_tool = diagnosis_result.get("fix_tool", "dism_restore")
            risk = diagnosis_result.get("risk", "safe")
            diagnosis = diagnosis_result.get("diagnosis", "")

            save_cached_diagnosis(
                source=source,
                message_fingerprint=fingerprint,
                diagnosis=diagnosis,
                fix_tool=fix_tool,
                fix_action=diagnosis_result.get("fix_action", ""),
                risk=risk,
                confidence=diagnosis_result.get("confidence", "low")
            )

        # Skip manual only
        if fix_tool == "manual_only":
            print(f"[WATCHER] Manual intervention required for {source}")
            notify_realtime_fix(source, fix_tool, success=False)
            log_agent_action(
                action="watcher_manual_escalation",
                reasoning=f"Critical event from {source} requires manual fix",
                outcome=diagnosis
            )
            return

        # Attempt fix
        print(f"[WATCHER] Applying fix: {fix_tool}")
        result = execute_fix(fix_tool, risk)
        success = result.get("success", False)

        update_cache_success(source, fingerprint, succeeded=success)

        if success:
            print(f"[WATCHER] Critical event from {source} fixed successfully")
            log_agent_action(
                action="watcher_fix_applied",
                reasoning=f"Real-time fix for critical event from {source}",
                outcome=f"Success using {fix_tool}"
            )
        else:
            print(f"[WATCHER] Could not fix critical event from {source}")
            log_agent_action(
                action="watcher_fix_failed",
                reasoning=f"Real-time fix failed for {source}",
                outcome=result.get("output", "")[:200]
            )

        notify_realtime_fix(source, fix_tool, success=success)

    def _is_in_cooldown(self, fingerprint: str) -> bool:
        """Check if this error was handled recently."""
        if fingerprint not in self._recently_handled:
            return False
        last_handled = self._recently_handled[fingerprint]
        cooldown = timedelta(minutes=self._cooldown_minutes)
        if datetime.now() - last_handled < cooldown:
            return True
        # Cooldown expired — remove from tracking
        del self._recently_handled[fingerprint]
        return False


# Single global instance
watcher = RealTimeEventWatcher()