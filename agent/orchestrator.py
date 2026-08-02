import time
from datetime import datetime
from config.settings import MAX_REMEDIATION_ATTEMPTS, AUTO_INSTALL_RISK_LEVELS
from tools.patch_tools import (
    get_pending_updates,
    get_installed_patches,
    get_known_issues,
    install_pending_updates,
    generate_patch_report,
    get_installed_patch_registry,
    check_patch_against_bug_db,
    generate_audit_report,
    get_windows_update_history
)
from database.db import (
    log_agent_action,
    save_patch,
    get_all_patches,
    save_remediation
)
from agent.llm import assess_patch_risk, diagnose_system_error, analyze_root_cause
from tools.patch_tools import (
    get_pending_updates,
    get_installed_patches,
    get_known_issues,
    install_pending_updates,
    generate_patch_report,
    get_installed_patch_registry,
    check_patch_against_bug_db,
    generate_audit_report
)
from tools.system_tools import (
    get_event_logs,
    save_events_to_db,
    execute_fix,
    uninstall_patch
)


def run_historical_audit():
    """
    Phase 6 — Audit all installed patches against known bug databases.
    If bugs found: attempt root cause fix first.
    If fix fails after 3 attempts: uninstall the patch automatically.
    """
    print("\n[ORCHESTRATOR] ── Phase 6: Historical Patch Audit ──")
    log_agent_action(action="historical_audit_start", reasoning="Auditing all installed patches")

    installed = get_installed_patch_registry()

    if not installed:
        print("[ORCHESTRATOR] No installed patches found to audit")
        run_agent_cycle._last_audit = []
        return []

    print(f"[ORCHESTRATOR] Auditing {len(installed)} installed patches...")

    audit_results = []
    flagged_count = 0

    for patch in installed:
        kb_id = patch["kb_id"]
        result = check_patch_against_bug_db(kb_id)
        result["description"] = patch.get("description", "")
        result["installed_on"] = patch.get("installed_on", "")
        result["action_taken"] = "none"
        result["action_result"] = ""

        if result["has_issues"]:
            flagged_count += 1
            print(f"\n[ORCHESTRATOR] Bug found in installed patch {kb_id}")
            print(f"[ORCHESTRATOR] Bug: {result['issues'][:100]}")

            from database.db import save_patch_bug
            save_patch_bug(
                kb_id=kb_id,
                bug_description=result["issues"],
                severity="Medium"
            )

            print(f"[ORCHESTRATOR] Running root cause analysis for {kb_id}...")
            rca = analyze_root_cause(kb_id, result["issues"], is_installed=True)

            print(f"[ORCHESTRATOR] Root cause: {rca.get('root_cause', '')}")
            print(f"[ORCHESTRATOR] Severity: {rca.get('severity')} | Can auto fix: {rca.get('can_auto_fix')} | Recommendation: {rca.get('recommendation')}")

            result["root_cause"] = rca.get("root_cause", "")
            result["severity"] = rca.get("severity", "Medium")
            result["recommendation"] = rca.get("recommendation", "monitor")
            result["manual_instructions"] = rca.get("manual_instructions", "")

            recommendation = rca.get("recommendation", "monitor")
            can_auto_fix = rca.get("can_auto_fix", "no")
            fix_tool = rca.get("fix_tool", "manual_only")

            fix_succeeded = False

            if can_auto_fix == "yes" and fix_tool != "manual_only":
                print(f"[ORCHESTRATOR] Attempting automatic fix for {kb_id} using {fix_tool}...")
                attempt = 0

                while attempt < MAX_REMEDIATION_ATTEMPTS and not fix_succeeded:
                    attempt += 1
                    print(f"[ORCHESTRATOR] Fix attempt {attempt}/{MAX_REMEDIATION_ATTEMPTS}")
                    fix_result = execute_fix(fix_tool, "safe")
                    fix_succeeded = fix_result.get("success", False)

                    if fix_succeeded:
                        print(f"[ORCHESTRATOR] Fix succeeded on attempt {attempt} — keeping patch {kb_id}")
                        result["action_taken"] = f"fixed_with_{fix_tool}"
                        result["action_result"] = "Fix successful — patch retained"
                        log_agent_action(
                            action="patch_bug_fixed",
                            reasoning=f"Fixed bug in {kb_id} using {fix_tool}",
                            outcome="Success — patch retained"
                        )
                    else:
                        print(f"[ORCHESTRATOR] Fix attempt {attempt} failed...")
                        time.sleep(5)

            if not fix_succeeded:
                if recommendation in ["uninstall", "fix_then_keep"]:
                    print(f"[ORCHESTRATOR] Fix failed — uninstalling {kb_id}...")
                    uninstall_result = uninstall_patch(kb_id)

                    if uninstall_result["success"]:
                        print(f"[ORCHESTRATOR] Successfully uninstalled {kb_id}")
                        result["action_taken"] = "uninstalled"
                        result["action_result"] = f"Patch uninstalled due to bug: {result['issues'][:100]}"
                        log_agent_action(
                            action="patch_uninstalled",
                            reasoning=f"Uninstalled {kb_id} — bug could not be fixed",
                            outcome="Success"
                        )
                    else:
                        print(f"[ORCHESTRATOR] Could not uninstall {kb_id} — providing manual instructions")
                        result["action_taken"] = "uninstall_failed"
                        result["action_result"] = "Automatic uninstall failed — see manual instructions below"
                        log_agent_action(
                            action="patch_uninstall_failed",
                            reasoning=f"Could not uninstall {kb_id}",
                            outcome=uninstall_result.get("output", "")
                        )
                else:
                    print(f"[ORCHESTRATOR] Monitoring {kb_id} — no action taken")
                    result["action_taken"] = "manual_required"
                    result["action_result"] = rca.get("manual_instructions", "Manual investigation required")

        else:
            print(f"[ORCHESTRATOR] ✓ {kb_id} — clean")

        audit_results.append(result)

    report_path = generate_audit_report(audit_results)
    print(f"\n[ORCHESTRATOR] Audit complete — {flagged_count} patches flagged out of {len(installed)}")
    print(f"[ORCHESTRATOR] Audit report: {report_path}")

    log_agent_action(
        action="historical_audit_complete",
        outcome=f"Audited {len(installed)} patches, flagged {flagged_count}"
    )

    run_agent_cycle._last_audit = audit_results
    return audit_results


def run_patch_detection() -> list:
    """
    Step 1 — Detect new patches and assess their risk.
    If bugs found: attempt root cause fix first before deciding to install.
    Returns list of assessed patches.
    """
    print("\n[ORCHESTRATOR] ── Step 1: Patch Detection ──")
    log_agent_action(action="patch_detection_start", reasoning="Agent cycle started")

    pending = get_pending_updates()

    if not pending:
        print("[ORCHESTRATOR] No pending updates found.")
        log_agent_action(action="patch_detection_complete", outcome="No pending updates")
        return []

    assessed_patches = []

    for update in pending:
        title = update.get("Title", "Unknown")
        kb_ids_raw = update.get("KBArticleIDs", "")

        if isinstance(kb_ids_raw, list):
            kb_id = str(kb_ids_raw[0]) if kb_ids_raw else "UNKNOWN"
        elif isinstance(kb_ids_raw, str) and kb_ids_raw:
            kb_id = kb_ids_raw.split(",")[0].strip()
        else:
            kb_id = "UNKNOWN"

        if kb_id and not kb_id.upper().startswith("KB"):
            kb_id = f"KB{kb_id}"

        print(f"\n[ORCHESTRATOR] Assessing patch: {kb_id} — {title}")

        known_issues = get_known_issues(kb_id)
        has_bugs = (
            known_issues and
            "No known issues" not in known_issues and
            "Could not retrieve" not in known_issues
        )

        rca = None

        if has_bugs:
            print(f"[ORCHESTRATOR] Bugs detected in {kb_id} — running root cause analysis before download...")
            rca = analyze_root_cause(kb_id, known_issues, is_installed=False)
            print(f"[ORCHESTRATOR] Root cause: {rca.get('root_cause', '')}")
            print(f"[ORCHESTRATOR] Severity: {rca.get('severity')} | Recommendation: {rca.get('recommendation')}")

            can_auto_fix = rca.get("can_auto_fix", "no")
            fix_tool = rca.get("fix_tool", "manual_only")
            fix_succeeded = False

            if can_auto_fix == "yes" and fix_tool != "manual_only":
                print(f"[ORCHESTRATOR] Attempting to fix root cause before downloading {kb_id}...")
                attempt = 0
                while attempt < MAX_REMEDIATION_ATTEMPTS and not fix_succeeded:
                    attempt += 1
                    fix_result = execute_fix(fix_tool, "safe")
                    fix_succeeded = fix_result.get("success", False)
                    if not fix_succeeded:
                        time.sleep(5)

                if fix_succeeded:
                    print(f"[ORCHESTRATOR] Root cause fixed — proceeding with {kb_id} download")
                else:
                    print(f"[ORCHESTRATOR] Could not fix root cause — skipping download of {kb_id}")
                    assessed_patches.append({
                        "kb_id": kb_id,
                        "title": title,
                        "risk_level": rca.get("severity", "High"),
                        "reasoning": rca.get("root_cause", ""),
                        "recommendation": "skip_install",
                        "status": "skipped",
                        "manual_instructions": rca.get("manual_instructions", "")
                    })
                    save_patch(
                        kb_id=kb_id,
                        title=title,
                        release_date=str(datetime.now().date()),
                        risk_level=rca.get("severity", "High"),
                        risk_reasoning=rca.get("root_cause", ""),
                        status="skipped"
                    )
                    continue

            elif can_auto_fix == "no":
                recommendation = rca.get("recommendation", "skip_install")
                if recommendation in ["skip_install", "uninstall"]:
                    print(f"[ORCHESTRATOR] Cannot auto fix — not downloading {kb_id}")
                    assessed_patches.append({
                        "kb_id": kb_id,
                        "title": title,
                        "risk_level": rca.get("severity", "High"),
                        "reasoning": rca.get("root_cause", ""),
                        "recommendation": "skip_install",
                        "status": "skipped",
                        "manual_instructions": rca.get("manual_instructions", "")
                    })
                    save_patch(
                        kb_id=kb_id,
                        title=title,
                        release_date=str(datetime.now().date()),
                        risk_level=rca.get("severity", "High"),
                        risk_reasoning=rca.get("root_cause", ""),
                        status="skipped"
                    )
                    continue

        assessment = assess_patch_risk(kb_id, title, known_issues)
        risk_level = assessment.get("risk_level", "Medium")
        reasoning = assessment.get("reasoning", "")
        recommendation = assessment.get("recommendation", "hold")

        print(f"[ORCHESTRATOR] Risk: {risk_level} — {reasoning}")

        save_patch(
            kb_id=kb_id,
            title=title,
            release_date=str(datetime.now().date()),
            risk_level=risk_level,
            risk_reasoning=reasoning,
            status="detected"
        )

        assessed_patches.append({
            "kb_id": kb_id,
            "title": title,
            "risk_level": risk_level,
            "reasoning": reasoning,
            "recommendation": recommendation,
            "status": "detected",
            "manual_instructions": rca.get("manual_instructions", "") if rca else ""
        })

    log_agent_action(
        action="patch_detection_complete",
        outcome=f"Assessed {len(assessed_patches)} patches"
    )

    return assessed_patches


def run_patch_installation(assessed_patches: list) -> list:
    """
    Step 2 — Install patches that are Low or Medium risk.
    Holds High risk patches and logs them.
    """
    print("\n[ORCHESTRATOR] ── Step 2: Patch Installation ──")

    installed = []
    held = []

    for patch in assessed_patches:
        kb_id = patch["kb_id"]
        risk = patch["risk_level"]
        recommendation = patch["recommendation"]

        if risk == "High" or recommendation in ["hold", "skip_install"]:
            print(f"[ORCHESTRATOR] HOLDING patch {kb_id} — risk too high or bugs present")
            log_agent_action(
                action="patch_held",
                reasoning=f"Patch {kb_id} held — risk level: {risk}",
                outcome="Patch held for manual review"
            )
            held.append(patch)
            continue

        if risk in AUTO_INSTALL_RISK_LEVELS:
            print(f"[ORCHESTRATOR] Installing patch {kb_id} — risk: {risk}")
            log_agent_action(
                action="patch_install_start",
                reasoning=f"Installing {kb_id} — risk level acceptable: {risk}"
            )

            result = install_pending_updates()

            if result["success"]:
                print(f"[ORCHESTRATOR] Patch {kb_id} installed successfully")
                patch["status"] = "installed"
                installed.append(patch)
                save_patch(
                    kb_id=kb_id,
                    title=patch.get("title", ""),
                    release_date=str(datetime.now().date()),
                    risk_level=patch.get("risk_level", ""),
                    risk_reasoning=patch.get("reasoning", ""),
                    status="installed"
                )
                log_agent_action(
                    action="patch_install_complete",
                    reasoning=f"Patch {kb_id} installed",
                    outcome="Success"
                )
                if result.get("reboot_required"):
                    print(f"[ORCHESTRATOR] WARNING: Reboot required after installing {kb_id}")
            else:
                print(f"[ORCHESTRATOR] ERROR: Failed to install {kb_id}")
                patch["status"] = "failed"
                log_agent_action(
                    action="patch_install_failed",
                    reasoning=f"Patch {kb_id} installation failed",
                    outcome=result.get("output", "Unknown error")
                )

    print(f"[ORCHESTRATOR] Installed: {len(installed)} | Held: {len(held)}")
    return installed


def run_monitoring(installed_patches: list) -> list:
    """
    Step 3 — Monitor Windows Event Log for errors after patch installation.
    """
    print("\n[ORCHESTRATOR] ── Step 3: Post-Install Monitoring ──")

    linked_kb_id = installed_patches[-1]["kb_id"] if installed_patches else ""
    events = get_event_logs()

    if not events:
        print("[ORCHESTRATOR] No errors found in event logs.")
        log_agent_action(action="monitoring_complete", outcome="No errors detected")
        return []

    save_events_to_db(events, linked_kb_id)
    print(f"[ORCHESTRATOR] Found {len(events)} errors to investigate")
    log_agent_action(action="monitoring_complete", outcome=f"Found {len(events)} error events")

    return events


def run_remediation(events: list) -> list:
    """
    Step 4 — Diagnose each error and apply fixes.
    Checks local cache first — only calls LLM for new errors.
    Saves all new diagnoses to cache permanently.
    """
    print("\n[ORCHESTRATOR] ── Step 4: Remediation ──")

    from database.db import get_cached_diagnosis, save_cached_diagnosis, update_cache_success
    from agent.llm import get_message_fingerprint

    fix_results = []
    cache_hits = 0
    llm_calls = 0

    manual_only_conditions = [
        "hardware", "bios", "firmware", "physical",
        "motherboard", "power supply", "ram failure",
        "cpu", "overheating", "disk failure"
    ]

    for i, event in enumerate(events[:5]):
        message = event.get("message", "")
        linked_kb = event.get("linked_kb_id", "")
        source = event.get("source", "Unknown")

        print(f"\n[ORCHESTRATOR] Diagnosing error {i+1}: {source}")

        # Generate fingerprint for cache lookup
        fingerprint = get_message_fingerprint(source, message)

        # Check cache first
        cached = get_cached_diagnosis(source, fingerprint)

        if cached:
            cache_hits += 1
            fix_tool = cached["fix_tool"]
            fix_action = cached["fix_action"]
            risk = cached["risk"]
            diagnosis_text = cached["diagnosis"]
            print(f"[ORCHESTRATOR] Cache hit — skipping LLM call")
            print(f"[ORCHESTRATOR] Cached diagnosis: {diagnosis_text}")
            print(f"[ORCHESTRATOR] Cached fix: {fix_tool}")
        else:
            llm_calls += 1
            print(f"[ORCHESTRATOR] New error — sending to LLM for diagnosis...")
            diagnosis = diagnose_system_error(message, linked_kb)
            fix_tool = diagnosis.get("fix_tool", "dism_restore")
            fix_action = diagnosis.get("fix_action", "")
            risk = diagnosis.get("risk", "safe")
            diagnosis_text = diagnosis.get("diagnosis", "")
            confidence = diagnosis.get("confidence", "low")

            print(f"[ORCHESTRATOR] Diagnosis: {diagnosis_text}")
            print(f"[ORCHESTRATOR] Fix tool: {fix_tool} | Risk: {risk} | Confidence: {confidence}")

            # Save to cache immediately for next time
            save_cached_diagnosis(
                source=source,
                message_fingerprint=fingerprint,
                diagnosis=diagnosis_text,
                fix_tool=fix_tool,
                fix_action=fix_action,
                risk=risk,
                confidence=confidence
            )
            print(f"[ORCHESTRATOR] Diagnosis saved to cache — will not call LLM for this error again")

        # Check if genuinely manual
        message_lower = (message + " " + diagnosis_text).lower()
        is_truly_manual = any(word in message_lower for word in manual_only_conditions)

        if fix_tool == "manual_only" and not is_truly_manual:
            print(f"[ORCHESTRATOR] Overriding manual_only → dism_restore")
            fix_tool = "dism_restore"
            risk = "safe"

        if fix_tool == "manual_only" and is_truly_manual:
            print(f"[ORCHESTRATOR] Genuine manual intervention required — {source}")
            fix_results.append({
                "tool": "manual_only",
                "output": fix_action,
                "success": False,
                "source": source,
                "diagnosis": diagnosis_text,
                "from_cache": cached is not None
            })
            continue

        # Execute fix
        attempt = 0
        success = False
        result = {"output": "", "success": False}

        while attempt < MAX_REMEDIATION_ATTEMPTS and not success:
            attempt += 1
            print(f"[ORCHESTRATOR] Fix attempt {attempt}/{MAX_REMEDIATION_ATTEMPTS} using {fix_tool}")

            result = execute_fix(fix_tool, risk)
            success = result.get("success", False)

            save_remediation(
                linked_event_id=i,
                action_taken=fix_action,
                tool_used=fix_tool,
                result=result.get("output", ""),
                success=success
            )

            if success:
                print(f"[ORCHESTRATOR] Fix successful on attempt {attempt}")
                update_cache_success(source, fingerprint, succeeded=True)
                break
            else:
                print(f"[ORCHESTRATOR] Attempt {attempt} failed — retrying in 5s...")
                time.sleep(5)

        if not success:
            # Update fail count — will delete cache if fails 3 times total
            update_cache_success(source, fingerprint, succeeded=False)

            # Try fallback
            fallback = "restart_service" if fix_tool != "restart_service" else "dism_restore"
            print(f"[ORCHESTRATOR] Primary fix failed — trying fallback: {fallback}")

            fallback_result = execute_fix(fallback, "safe")
            if fallback_result.get("success"):
                print(f"[ORCHESTRATOR] Fallback {fallback} succeeded")
                result = fallback_result
                success = True
                fix_tool = fallback
                save_remediation(
                    linked_event_id=i,
                    action_taken=f"Fallback: {fallback}",
                    tool_used=fallback,
                    result=fallback_result.get("output", ""),
                    success=True
                )
            else:
                print(f"[ORCHESTRATOR] All attempts failed — escalating to user")
                log_agent_action(
                    action="remediation_escalated",
                    reasoning=f"All fix attempts failed for {source}",
                    outcome=f"Tool: {fix_tool}, Fallback: {fallback}"
                )

        fix_results.append({
            "tool": fix_tool,
            "output": result.get("output", ""),
            "success": success,
            "source": source,
            "diagnosis": diagnosis_text,
            "from_cache": cached is not None
        })

    print(f"\n[ORCHESTRATOR] Remediation summary — Cache hits: {cache_hits} | LLM calls: {llm_calls}")
    log_agent_action(
        action="remediation_complete",
        outcome=f"Cache hits: {cache_hits}, LLM calls: {llm_calls}, Events: {len(events)}"
    )

    return fix_results


def run_agent_cycle():
    """
    Main agent cycle — runs all steps in sequence.
    This is what the scheduler calls every 6 hours.
    """
    cycle_start = time.time()
    print(f"\n{'='*60}")
    print(f"[ORCHESTRATOR] AGENT CYCLE STARTED — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    log_agent_action(action="cycle_start", reasoning="Scheduled agent cycle began")

    try:
        # Phase 6 — Historical audit
        run_historical_audit()

        # Step 1 — Detect and assess patches
        assessed_patches = run_patch_detection()

        # Step 2 — Install safe patches
        installed_patches = run_patch_installation(assessed_patches)

        # Step 3 — Monitor for errors
        events = run_monitoring(installed_patches)

        # Step 4 — Diagnose and fix errors
        fix_results = run_remediation(events) if events else []

        # Step 5 — Generate combined report
        all_patches = [dict(p) for p in get_all_patches()]
        audit_results = getattr(run_agent_cycle, "_last_audit", [])
        update_history = get_windows_update_history()
        report_path = generate_patch_report(
            patches=all_patches,
            issues=events,
            fixes=fix_results,
            audit_results=audit_results,
            update_history=update_history
        )

        duration = int(time.time() - cycle_start)
        print(f"\n[ORCHESTRATOR] CYCLE COMPLETE in {duration}s")
        print(f"[ORCHESTRATOR] Report saved to: {report_path}")

        log_agent_action(
            action="cycle_complete",
            outcome=f"Patches: {len(assessed_patches)}, Events: {len(events)}, Fixes: {len(fix_results)}",
            duration_ms=duration * 1000
        )

    except Exception as e:
        print(f"\n[ORCHESTRATOR] CRITICAL ERROR in agent cycle: {e}")
        log_agent_action(
            action="cycle_error",
            outcome=f"Critical error: {e}"
        )