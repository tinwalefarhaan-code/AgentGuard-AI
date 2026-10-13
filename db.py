"""Persistent SQLite scan history and metrics storage for AgentGuard AI.

Provides thread-safe persistence, automatic schema initialization,
and privacy-preserving input sanitization (redacting credentials,
API keys, tokens, and sensitive personal identifiers).
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional

DEFAULT_DB_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "agentguard.db"

_DB_LOCK = threading.Lock()


def get_db_path() -> Path:
    """Return the configured database path."""
    custom = os.environ.get("AGENTGUARD_DB_PATH")
    if custom:
        return Path(custom)
    return DEFAULT_DB_PATH


def redact_sensitive_content(text: str) -> str:
    """Sanitize text by redacting credentials, tokens, and secrets before saving.

    Never store plain text passwords, API keys, private keys, or tokens.
    """
    if not text:
        return ""

    sanitized = text

    # Redact common key=value assignments (passwords, tokens, api keys)
    sanitized = re.sub(
        r"(?i)\b(api[_-]?key|access[_-]?token|secret[_-]?key|password|passwd|auth[_-]?token|private[_-]?key)"
        r"\s*[:=]\s*([^\s,;\"']+)",
        r"\1=[REDACTED]",
        sanitized,
    )

    # Redact HTTP Bearer tokens
    sanitized = re.sub(
        r"(?i)\bbearer\s+[a-z0-9._~+/=-]+",
        "Bearer [REDACTED]",
        sanitized,
    )

    # Redact common cloud provider API key prefixes (e.g. OpenAI, AWS, GitHub)
    sanitized = re.sub(
        r"\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b",
        "[REDACTED_API_KEY]",
        sanitized,
    )

    # Redact potential private keys
    sanitized = re.sub(
        r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY]",
        sanitized,
        flags=re.DOTALL,
    )

    # Redact potential credit card numbers (13-16 digits separated by dashes or spaces)
    sanitized = re.sub(
        r"\b(?:\d{4}[ -]?){3}\d{4}\b",
        "[REDACTED_CARD_NUMBER]",
        sanitized,
    )

    # Redact potential Social Security Numbers (SSN)
    sanitized = re.sub(
        r"\b\d{3}-\d{2}-\d{4}\b",
        "[REDACTED_SSN]",
        sanitized,
    )

    # Limit stored length to prevent database bloat and excessive data retention
    max_len = 500
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len] + "... [truncated for storage]"

    return sanitized


def init_db(db_path: Optional[Path | str] = None) -> Path:
    """Initialize the SQLite database with required tables and indexes."""
    path = Path(db_path) if db_path else get_db_path()

    with _DB_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'agent',
                    request TEXT NOT NULL,
                    tool TEXT NOT NULL DEFAULT '',
                    decision TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    threats TEXT NOT NULL DEFAULT '[]',
                    reason TEXT NOT NULL DEFAULT '',
                    recommended_action TEXT NOT NULL DEFAULT '',
                    action TEXT NOT NULL DEFAULT ''
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp DESC);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_history_mode ON scan_history(mode);"
            )
            conn.commit()
        finally:
            conn.close()

    return path


def save_scan_event(event: dict[str, Any], db_path: Optional[Path | str] = None) -> int:
    """Save a sanitized scan event to the database.

    Returns the inserted record's row ID.
    """
    path = Path(db_path) if db_path else get_db_path()
    if not path.exists():
        init_db(path)

    # Sanitize inputs before saving
    raw_request = event.get("request", "")
    sanitized_request = redact_sensitive_content(raw_request)

    mode = str(event.get("mode", "agent"))
    tool = str(event.get("tool", ""))
    decision = str(event.get("decision", "REVIEW"))
    risk_score = int(event.get("risk_score", 0))
    threats = event.get("threats", [])
    threats_json = json.dumps(threats if isinstance(threats, list) else [])
    reason = str(event.get("reason", ""))
    recommended_action = str(event.get("recommended_action", ""))
    action = str(event.get("action", ""))
    timestamp = str(event.get("timestamp", ""))

    with _DB_LOCK:
        conn = sqlite3.connect(str(path), timeout=10.0)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_history (
                    timestamp, mode, request, tool, decision,
                    risk_score, threats, reason, recommended_action, action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    timestamp,
                    mode,
                    sanitized_request,
                    tool,
                    decision,
                    risk_score,
                    threats_json,
                    reason,
                    recommended_action,
                    action,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0
        finally:
            conn.close()


def get_recent_scans(
    limit: int = 100,
    mode: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> list[dict[str, Any]]:
    """Retrieve recent scan events from the database."""
    path = Path(db_path) if db_path else get_db_path()
    if not path.exists():
        init_db(path)

    with _DB_LOCK:
        conn = sqlite3.connect(str(path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            if mode:
                cursor.execute(
                    """
                    SELECT id, timestamp, mode, request, tool, decision,
                           risk_score, threats, reason, recommended_action, action
                    FROM scan_history
                    WHERE mode = ?
                    ORDER BY id DESC
                    LIMIT ?;
                    """,
                    (mode, max(1, min(limit, 500))),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, timestamp, mode, request, tool, decision,
                           risk_score, threats, reason, recommended_action, action
                    FROM scan_history
                    ORDER BY id DESC
                    LIMIT ?;
                    """,
                    (max(1, min(limit, 500)),),
                )

            rows = cursor.fetchall()
            events = []
            for row in rows:
                try:
                    threats = json.loads(row["threats"])
                except Exception:
                    threats = []

                events.append(
                    {
                        "id": row["id"],
                        "timestamp": row["timestamp"],
                        "mode": row["mode"],
                        "request": row["request"],
                        "tool": row["tool"],
                        "decision": row["decision"],
                        "risk_score": row["risk_score"],
                        "threats": threats,
                        "reason": row["reason"],
                        "recommended_action": row["recommended_action"],
                        "action": row["action"],
                    }
                )
            return events
        finally:
            conn.close()


def get_metrics(db_path: Optional[Path | str] = None) -> dict[str, int]:
    """Calculate aggregate scan metrics directly from the persistent database."""
    path = Path(db_path) if db_path else get_db_path()
    if not path.exists():
        init_db(path)

    with _DB_LOCK:
        conn = sqlite3.connect(str(path), timeout=10.0)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scan_history;")
            scanned = cursor.fetchone()[0] or 0

            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE decision = 'ALLOW';")
            allowed = cursor.fetchone()[0] or 0

            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE decision = 'REVIEW';")
            review = cursor.fetchone()[0] or 0

            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE decision = 'BLOCK';")
            blocked = cursor.fetchone()[0] or 0

            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE risk_score >= 70;")
            high_risk = cursor.fetchone()[0] or 0

            return {
                "scanned": scanned,
                "allowed": allowed,
                "review": review,
                "blocked": blocked,
                "high_risk": high_risk,
            }
        finally:
            conn.close()


def clear_history(db_path: Optional[Path | str] = None) -> bool:
    """Clear all scan records from the database."""
    path = Path(db_path) if db_path else get_db_path()
    if not path.exists():
        init_db(path)
        return True

    with _DB_LOCK:
        conn = sqlite3.connect(str(path), timeout=10.0)
        try:
            conn.execute("DELETE FROM scan_history;")
            conn.commit()
            return True
        finally:
            conn.close()
