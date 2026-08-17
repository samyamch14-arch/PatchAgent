from winotify import Notification, audio
import os


APP_ID = "PatchAgent"
ICON_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "icon.png")


def _notify(title: str, message: str, sound: str = "default", duration: str = "short"):
    """
    Base notification function.
    duration: 'short' (5 seconds) or 'long' (25 seconds)
    """
    try:
        toast = Notification(
            app_id=APP_ID,
            title=title,
            msg=message[:200],
            duration=duration,
            icon=ICON_PATH if os.path.exists(ICON_PATH) else ""
        )
        if sound == "default":
            toast.set_audio(audio.Default, loop=False)
        elif sound == "silent":
            pass
        toast.show()
    except Exception as e:
        print(f"[NOTIFIER] Could not show notification: {e}")


def notify_cycle_started():
    _notify(
        title="PatchAgent — Cycle Started",
        message="Agent is checking for patches and scanning your system.",
        sound="silent"
    )


def notify_cycle_complete(installed: int, fixed: int, duration: int):
    _notify(
        title="PatchAgent — Cycle Complete",
        message=f"Installed: {installed} patch(es) · Fixed: {fixed} error(s) · Completed in {duration}s",
        sound="silent"
    )


def notify_patch_installed(kb_id: str, title: str):
    _notify(
        title=f"PatchAgent — Patch Installed ✓",
        message=f"{kb_id} installed successfully.\n{title[:100]}",
        sound="default"
    )


def notify_patch_held(kb_id: str, reason: str):
    _notify(
        title=f"PatchAgent — High Risk Patch Held ⚠",
        message=f"{kb_id} was held — risk too high.\nReason: {reason[:120]}",
        duration="long",
        sound="default"
    )


def notify_bug_found(kb_id: str, severity: str):
    _notify(
        title=f"PatchAgent — Bug Found in {kb_id} ⚠",
        message=f"A known bug was detected in installed patch {kb_id}.\nSeverity: {severity}. Agent is remediating.",
        duration="long",
        sound="default"
    )


def notify_patch_uninstalled(kb_id: str):
    _notify(
        title=f"PatchAgent — Patch Uninstalled",
        message=f"{kb_id} was automatically uninstalled due to an unfixable bug.\nA restore point was created first.",
        duration="long",
        sound="default"
    )


def notify_error_fixed(source: str, fix_tool: str, from_cache: bool):
    cache_text = "from cache — instant fix" if from_cache else "diagnosed by LLM"
    _notify(
        title="PatchAgent — Error Fixed ✓",
        message=f"Error from {source} resolved using {fix_tool} ({cache_text}).",
        sound="silent"
    )


def notify_error_escalated(source: str, reason: str):
    _notify(
        title="PatchAgent — Manual Action Required ⚠",
        message=f"Could not auto-fix error from {source}.\n{reason[:120]}",
        duration="long",
        sound="default"
    )


def notify_failed_update_fixed(kb_id: str):
    _notify(
        title=f"PatchAgent — Failed Update Recovered ✓",
        message=f"{kb_id} previously failed but was successfully installed after cache clear.",
        sound="default"
    )


def notify_security_patch_warning(kb_id: str, message: str):
    _notify(
        title=f"PatchAgent — Security Patch Issue ⚠",
        message=f"{kb_id} has a known bug but cannot be uninstalled — it is a security patch.\n{message[:120]}",
        duration="long",
        sound="default"
    )


def notify_agent_error(error: str):
    _notify(
        title="PatchAgent — Critical Error",
        message=f"Agent cycle failed: {error[:150]}\nCheck logs for details.",
        duration="long",
        sound="default"
    )
def notify_realtime_fix(source: str, fix_tool: str, success: bool):
    if success:
        _notify(
            title="PatchAgent — Real-time Fix Applied ✓",
            message=f"Critical error from {source} was detected and fixed immediately using {fix_tool}.",
            sound="default",
            duration="long"
        )
    else:
        _notify(
            title="PatchAgent — Critical Error Detected ⚠",
            message=f"Critical error from {source} could not be fixed automatically. Check your report.",
            sound="default",
            duration="long"
        )    