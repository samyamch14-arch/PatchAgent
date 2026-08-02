import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "patch_agent.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kb_id TEXT UNIQUE NOT NULL,
            title TEXT,
            release_date TEXT,
            status TEXT DEFAULT 'detected',
            risk_level TEXT DEFAULT 'Unknown',
            risk_reasoning TEXT,
            install_date TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patch_bugs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kb_id TEXT NOT NULL,
            bug_description TEXT,
            severity TEXT,
            discovered_date TEXT DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            channel TEXT,
            event_id INTEGER,
            source TEXT,
            message TEXT,
            linked_kb_id TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            linked_event_id INTEGER,
            action_taken TEXT,
            tool_used TEXT,
            result TEXT,
            success INTEGER DEFAULT 0,
            timestamp TEXT DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now')),
            action TEXT,
            reasoning TEXT,
            outcome TEXT,
            duration_ms INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_date TEXT DEFAULT (datetime('now')),
            report_type TEXT,
            content_path TEXT,
            summary TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS error_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            message_fingerprint TEXT NOT NULL,
            diagnosis TEXT,
            fix_tool TEXT,
            fix_action TEXT,
            risk TEXT,
            confidence TEXT,
            success_count INTEGER DEFAULT 0,
            fail_count INTEGER DEFAULT 0,
            last_used TEXT DEFAULT (datetime('now')),
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(source, message_fingerprint)
        )
    """)

    conn.commit()
    conn.close()
    print(f"[DB] Database initialized at {DB_PATH}")


def log_agent_action(action: str, reasoning: str = "", outcome: str = "", duration_ms: int = 0):
    conn = get_connection()
    conn.execute("""
        INSERT INTO agent_log (action, reasoning, outcome, duration_ms)
        VALUES (?, ?, ?, ?)
    """, (action, reasoning, outcome, duration_ms))
    conn.commit()
    conn.close()


def save_patch(kb_id: str, title: str, release_date: str, risk_level: str, risk_reasoning: str, status: str = "detected"):
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO patches (kb_id, title, release_date, risk_level, risk_reasoning, status)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(kb_id) DO UPDATE SET
                title = excluded.title,
                risk_level = excluded.risk_level,
                risk_reasoning = excluded.risk_reasoning,
                status = excluded.status,
                install_date = CASE WHEN excluded.status = 'installed' THEN datetime('now') ELSE install_date END
        """, (kb_id, title, release_date, risk_level, risk_reasoning, status))
        conn.commit()
    finally:
        conn.close()


def get_all_patches():
    conn = get_connection()
    patches = conn.execute("SELECT * FROM patches ORDER BY created_at DESC").fetchall()
    conn.close()
    return patches


def save_system_event(timestamp: str, channel: str, event_id: int, source: str, message: str, linked_kb_id: str = ""):
    conn = get_connection()
    cursor = conn.execute("""
        INSERT INTO system_events (timestamp, channel, event_id, source, message, linked_kb_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (timestamp, channel, event_id, source, message, linked_kb_id))
    conn.commit()
    event_row_id = cursor.lastrowid
    conn.close()
    return event_row_id


def save_remediation(linked_event_id: int, action_taken: str, tool_used: str, result: str, success: bool):
    conn = get_connection()
    conn.execute("""
        INSERT INTO remediations (linked_event_id, action_taken, tool_used, result, success)
        VALUES (?, ?, ?, ?, ?)
    """, (linked_event_id, action_taken, tool_used, result, 1 if success else 0))
    conn.commit()
    conn.close()


def save_patch_bug(kb_id: str, bug_description: str, severity: str = "Unknown"):
    conn = get_connection()
    conn.execute("""
        INSERT INTO patch_bugs (kb_id, bug_description, severity)
        VALUES (?, ?, ?)
    """, (kb_id, bug_description, severity))
    conn.commit()
    conn.close()


def get_all_installed_by_agent() -> list:
    conn = get_connection()
    patches = conn.execute("""
        SELECT * FROM patches
        WHERE status = 'installed'
        ORDER BY install_date DESC, created_at DESC
    """).fetchall()
    conn.close()
    return [dict(p) for p in patches]


def get_all_failed_by_agent() -> list:
    conn = get_connection()
    patches = conn.execute("""
        SELECT * FROM patches
        WHERE status = 'failed'
        ORDER BY created_at DESC
    """).fetchall()
    conn.close()
    return [dict(p) for p in patches]


def get_all_agent_actions() -> list:
    conn = get_connection()
    actions = conn.execute("""
        SELECT * FROM agent_log
        ORDER BY timestamp DESC
    """).fetchall()
    conn.close()
    return [dict(a) for a in actions]


def get_cached_diagnosis(source: str, message_fingerprint: str) -> dict | None:
    conn = get_connection()
    try:
        result = conn.execute("""
            SELECT * FROM error_cache
            WHERE source = ? AND message_fingerprint = ?
            LIMIT 1
        """, (source, message_fingerprint)).fetchone()
        conn.close()
        return dict(result) if result else None
    except Exception:
        conn.close()
        return None


def save_cached_diagnosis(source: str, message_fingerprint: str, diagnosis: str,
                          fix_tool: str, fix_action: str, risk: str, confidence: str,
                          success_count: int = 0) -> None:
    conn = get_connection()
    try:
        conn.execute("""
            INSERT OR REPLACE INTO error_cache
            (source, message_fingerprint, diagnosis, fix_tool, fix_action, risk, confidence, success_count, last_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (source, message_fingerprint, diagnosis, fix_tool, fix_action, risk, confidence, success_count))
        conn.commit()
    finally:
        conn.close()


def update_cache_success(source: str, message_fingerprint: str, succeeded: bool) -> None:
    conn = get_connection()
    try:
        if succeeded:
            conn.execute("""
                UPDATE error_cache
                SET success_count = success_count + 1, last_used = datetime('now')
                WHERE source = ? AND message_fingerprint = ?
            """, (source, message_fingerprint))
            conn.commit()
        else:
            row = conn.execute("""
                SELECT fail_count FROM error_cache
                WHERE source = ? AND message_fingerprint = ?
            """, (source, message_fingerprint)).fetchone()

            if row:
                fail_count = (row["fail_count"] or 0) + 1
                if fail_count >= 3:
                    conn.execute("""
                        DELETE FROM error_cache
                        WHERE source = ? AND message_fingerprint = ?
                    """, (source, message_fingerprint))
                    print(f"[CACHE] Deleted stale cache entry for {source} — fix failed 3 times")
                else:
                    conn.execute("""
                        UPDATE error_cache
                        SET fail_count = ?
                        WHERE source = ? AND message_fingerprint = ?
                    """, (fail_count, source, message_fingerprint))
            conn.commit()
    finally:
        conn.close()


def get_cache_stats() -> dict:
    conn = get_connection()
    try:
        total = conn.execute("SELECT COUNT(*) as c FROM error_cache").fetchone()["c"]
        hits = conn.execute("SELECT SUM(success_count) as c FROM error_cache").fetchone()["c"] or 0
        conn.close()
        return {"total_entries": total, "total_hits": hits}
    except Exception:
        conn.close()
        return {"total_entries": 0, "total_hits": 0}