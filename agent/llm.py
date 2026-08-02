import requests
import json
import time
from config.settings import OLLAMA_BASE_URL, OLLAMA_MODEL
from database.db import log_agent_action


def query_llm(prompt: str, system_prompt: str = "") -> dict | None:
    """
    Send a prompt to OLLAMA and return parsed JSON response.
    Returns None if the call fails.
    """
    url = f"{OLLAMA_BASE_URL}/api/chat"

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "format": "json"
    }

    start_time = time.time()

    try:
        print(f"[LLM] Sending request to OLLAMA ({OLLAMA_MODEL})...")
        response = requests.post(url, json=payload, timeout=300)
        response.raise_for_status()

        duration_ms = int((time.time() - start_time) * 1000)
        raw = response.json()
        content = raw.get("message", {}).get("content", "")

        print(f"[LLM] Response received in {duration_ms}ms")

        parsed = json.loads(content)

        log_agent_action(
            action="llm_query",
            reasoning=prompt[:200],
            outcome=f"Success in {duration_ms}ms",
            duration_ms=duration_ms
        )

        return parsed

    except requests.exceptions.Timeout:
        print("[LLM] ERROR: Request timed out after 300 seconds")
        log_agent_action(action="llm_query", reasoning=prompt[:200], outcome="Timeout error")
        return None

    except json.JSONDecodeError as e:
        print(f"[LLM] ERROR: Could not parse JSON response — {e}")
        log_agent_action(action="llm_query", reasoning=prompt[:200], outcome=f"JSON parse error: {e}")
        return None

    except Exception as e:
        print(f"[LLM] ERROR: {e}")
        log_agent_action(action="llm_query", reasoning=prompt[:200], outcome=f"Error: {e}")
        return None
    
def get_message_fingerprint(source: str, message: str) -> str:
    """
    Create a stable fingerprint from an error message.
    Strips variable parts like hex codes, timestamps, memory addresses.
    Returns a short consistent string for cache lookup.
    """
    import re
    import hashlib

    # Remove variable parts
    cleaned = message.lower()
    cleaned = re.sub(r'0x[0-9a-f]+', 'HEXCODE', cleaned)       # hex codes
    cleaned = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', 'DATE', cleaned) # dates
    cleaned = re.sub(r'\b\d{2}:\d{2}:\d{2}\b', 'TIME', cleaned) # times
    cleaned = re.sub(r'\b\d+\.\d+\.\d+\.\d+\b', 'IP', cleaned)  # IP addresses
    cleaned = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 'GUID', cleaned)  # GUIDs
    cleaned = re.sub(r'\d+', 'N', cleaned)                        # all remaining numbers
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()                # normalize whitespace

    # Take first 120 chars for matching — captures the stable core
    core = (source.lower() + "|" + cleaned[:120])

    # Return short hash for DB storage
    return hashlib.md5(core.encode()).hexdigest()    


def assess_patch_risk(kb_id: str, title: str, known_issues: str) -> dict:
    """
    Ask the LLM to assess the risk level of a patch.
    Returns a dict with risk_level and reasoning.
    """
    system_prompt = """You are a Windows patch management AI agent.
Your job is to assess the risk of installing a Microsoft patch.
You must respond ONLY with valid JSON. No extra text, no markdown, no explanation outside the JSON."""

    prompt = f"""Assess the risk of installing this Microsoft patch.

KB ID: {kb_id}
Title: {title}
Known Issues: {known_issues if known_issues else "No known issues reported."}

You MUST respond with exactly this JSON. Use ONLY the exact values shown for each field:
{{
    "risk_level": "MUST be exactly one of these words: Low, Medium, High",
    "reasoning": "One or two sentences explaining why",
    "recommendation": "MUST be exactly one of these words: install, hold, skip"
}}"""

    result = query_llm(prompt, system_prompt)

    if not result:
        return {
            "risk_level": "Medium",
            "reasoning": "Could not assess — defaulting to Medium for safety.",
            "recommendation": "hold"
        }

    valid_risks = ["Low", "Medium", "High"]
    if result.get("risk_level") not in valid_risks:
        result["risk_level"] = "Medium"

    valid_recs = ["install", "hold", "skip"]
    if result.get("recommendation") not in valid_recs:
        result["recommendation"] = "hold"

    return result


def diagnose_system_error(event_message: str, linked_kb_id: str) -> dict:
    """
    Ask the LLM to diagnose a Windows event log error.
    Kept short for faster response on low-resource hardware.
    """
    system_prompt = """You are a Windows diagnostics agent. Respond ONLY in valid JSON. No extra text."""

    # Trim message to avoid slow LLM responses
    short_message = event_message[:200] if event_message else "Unknown error"

    prompt = f"""Diagnose this Windows error and pick the best fix tool.

Error: {short_message}
Patch: {linked_kb_id if linked_kb_id else "Unknown"}

Rules:
- Use dism_restore for file corruption, boot errors, integrity issues
- Use restart_service for service failures
- Use registry_fix for registry issues
- Only use manual_only for hardware or BIOS problems

Respond with ONLY this JSON, nothing else:
{{"diagnosis":"one sentence","fix_action":"one sentence","fix_tool":"dism_restore or restart_service or registry_fix or manual_only","risk":"safe or risky or manual_only","confidence":"high or medium or low"}}"""

    result = query_llm(prompt, system_prompt)

    if not result:
        return {
            "diagnosis": "Could not diagnose — running default repair.",
            "fix_action": "Running DISM restore as default action.",
            "fix_tool": "dism_restore",
            "risk": "safe",
            "confidence": "low"
        }

    # Validate all fields
    valid_tools = ["dism_restore", "restart_service", "registry_fix", "manual_only"]
    if result.get("fix_tool") not in valid_tools:
        result["fix_tool"] = "dism_restore"

    valid_risks = ["safe", "risky", "manual_only"]
    if result.get("risk") not in valid_risks:
        result["risk"] = "safe"

    valid_confidence = ["high", "medium", "low"]
    if result.get("confidence") not in valid_confidence:
        result["confidence"] = "low"

    # Override manual_only to dism_restore if not truly hardware issue
    message_lower = (short_message + " " + result.get("diagnosis", "")).lower()
    is_truly_manual = any(word in message_lower for word in [
        "hardware", "bios", "firmware", "physical",
        "motherboard", "power supply", "ram failure", "cpu", "overheating"
    ])

    if result.get("fix_tool") == "manual_only" and not is_truly_manual:
        result["fix_tool"] = "dism_restore"
        result["risk"] = "safe"

    if result.get("fix_tool") != "manual_only" and result.get("risk") == "manual_only":
        result["risk"] = "safe"

    return result


def analyze_root_cause(kb_id: str, bug_description: str, is_installed: bool) -> dict:
    """
    Perform deep root cause analysis on a patch bug.
    Returns root cause, fix plan, severity, and whether agent can fix it.
    """
    system_prompt = """You are a Windows patch management AI agent specializing in root cause analysis.
Your job is to analyze patch bugs, find their root cause, and determine if they can be fixed automatically.
You must respond ONLY with valid JSON. No extra text."""

    context = "already installed on the system" if is_installed else "pending installation"

    prompt = f"""Perform root cause analysis on this Windows patch bug.

KB ID: {kb_id}
Status: This patch is {context}
Bug Description: {bug_description}

Analyze the root cause and determine the best course of action.

You MUST respond with exactly this JSON. Use ONLY the exact values shown for each field:
{{
    "root_cause": "One clear sentence explaining WHY this bug exists",
    "severity": "MUST be exactly one of: Low, Medium, High, Critical",
    "can_auto_fix": "MUST be exactly one of: yes, no",
    "fix_steps": "Step by step fix actions the agent should take automatically if can_auto_fix is yes",
    "fix_tool": "MUST be exactly one of: dism_restore, restart_service, registry_fix, manual_only",
    "manual_instructions": "Detailed step by step instructions for the user if the agent cannot fix it automatically",
    "recommendation": "MUST be exactly one of: fix_then_keep, fix_then_install, uninstall, skip_install, monitor"
}}"""

    result = query_llm(prompt, system_prompt)

    if not result:
        return {
            "root_cause": "Could not determine root cause automatically.",
            "severity": "Medium",
            "can_auto_fix": "no",
            "fix_steps": "",
            "fix_tool": "manual_only",
            "manual_instructions": f"Manually investigate {kb_id} — check Windows Event Log and Microsoft support page for {kb_id}.",
            "recommendation": "monitor"
        }

    valid_severities = ["Low", "Medium", "High", "Critical"]
    if result.get("severity") not in valid_severities:
        result["severity"] = "Medium"

    valid_recommendations = ["fix_then_keep", "fix_then_install", "uninstall", "skip_install", "monitor"]
    if result.get("recommendation") not in valid_recommendations:
        result["recommendation"] = "monitor"

    valid_tools = ["dism_restore", "restart_service", "registry_fix", "manual_only"]
    if result.get("fix_tool") not in valid_tools:
        result["fix_tool"] = "manual_only"

    valid_auto = ["yes", "no"]
    if result.get("can_auto_fix") not in valid_auto:
        result["can_auto_fix"] = "no"

    return result