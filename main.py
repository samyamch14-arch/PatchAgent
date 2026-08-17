import sys
import os
import logging
from datetime import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger
from config.settings import AGENT_INTERVAL_HOURS, LOG_FILE, LOG_LEVEL, LOGS_DIR, REPORTS_DIR
from database.db import initialize_database, log_agent_action
from agent.orchestrator import run_agent_cycle
from agent.watcher import watcher


def setup_logging():
    """
    Configure logging to both terminal and log file.
    """
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    log_format = "%(asctime)s [%(levelname)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )

    print(f"[MAIN] Logging initialized — writing to {LOG_FILE}")


def startup_check():
    """
    Verify all required components are ready before starting.
    """
    print("\n[MAIN] Running startup checks...")

    # Check OLLAMA is running
    import requests
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            print("[MAIN] ✓ OLLAMA is running")
        else:
            print("[MAIN] ✗ OLLAMA responded with unexpected status")
            sys.exit(1)
    except Exception:
        print("[MAIN] ✗ OLLAMA is not running — start it with: ollama serve")
        sys.exit(1)

    # Check database
    try:
        initialize_database()
        print("[MAIN] ✓ Database initialized")
    except Exception as e:
        print(f"[MAIN] ✗ Database error: {e}")
        sys.exit(1)

    # Check reports and logs directories
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    print("[MAIN] ✓ Directories ready")

    print("[MAIN] All checks passed — agent is ready\n")


def main():
    print("=" * 60)
    print("  AUTONOMOUS PATCH MANAGEMENT AGENT")
    print("  Powered by OLLAMA + Phi-3 Mini")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Setup
    setup_logging()
    startup_check()
    # Start real-time watcher in background
    watcher.start()

    # Run one immediate cycle on startup
    print("[MAIN] Running initial cycle now...")
    run_agent_cycle()

    # Run one immediate cycle on startup
    print("[MAIN] Running initial cycle now...")
    run_agent_cycle()

    # Schedule recurring cycles
    scheduler = BlockingScheduler()
    scheduler.add_job(
        func=run_agent_cycle,
        trigger=IntervalTrigger(hours=AGENT_INTERVAL_HOURS),
        id="patch_agent_cycle",
        name="Patch Agent Cycle",
        replace_existing=True
    )

    print(f"\n[MAIN] Scheduler started — next cycle in {AGENT_INTERVAL_HOURS} hours")
    print("[MAIN] Press Ctrl+C to stop the agent\n")

    log_agent_action(
        action="agent_started",
        reasoning=f"Agent started — cycle interval: {AGENT_INTERVAL_HOURS} hours",
        outcome="Running"
    )

    try:
        scheduler.start()
    except KeyboardInterrupt:
        print("\n[MAIN] Agent stopped by user")
        log_agent_action(action="agent_stopped", outcome="Stopped by user")
        scheduler.shutdown()


if __name__ == "__main__":
    main()