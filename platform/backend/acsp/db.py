from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Iterable, Optional

from acsp.settings import get_settings

_init_lock = threading.Lock()


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    event_type TEXT NOT NULL,
    container_id TEXT NOT NULL DEFAULT '',
    raw_log TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_container ON events(container_id);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

CREATE TABLE IF NOT EXISTS audit_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    decision TEXT NOT NULL,
    detail_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_entries(event_id);

CREATE TABLE IF NOT EXISTS evaluation_labels (
    event_id TEXT PRIMARY KEY,
    is_true_positive INTEGER,
    notes TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id)
);

CREATE TABLE IF NOT EXISTS raw_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    line TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback_mismatches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    component TEXT NOT NULL,
    true_label TEXT NOT NULL,
    predicted TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    weights_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback_patterns (
    pattern_key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def _migrate_audit_entries_remove_fk(conn: sqlite3.Connection) -> None:
    """
    Older DBs used ``FOREIGN KEY (event_id) REFERENCES events(id)`` on ``audit_entries``.
    Pipeline audit rows are written before the event row exists, so that FK must not apply.
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_entries'"
    ).fetchone()
    if not row or not row[0] or "FOREIGN KEY" not in row[0].upper():
        return
    conn.executescript(
        """
        CREATE TABLE audit_entries__new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            stage TEXT NOT NULL,
            decision TEXT NOT NULL,
            detail_json TEXT,
            created_at TEXT NOT NULL
        );
        INSERT INTO audit_entries__new (id, event_id, stage, decision, detail_json, created_at)
            SELECT id, event_id, stage, decision, detail_json, created_at FROM audit_entries;
        DROP TABLE audit_entries;
        ALTER TABLE audit_entries__new RENAME TO audit_entries;
        CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_entries(event_id);
        """
    )


def _migrate_event_research_columns(conn: sqlite3.Connection) -> None:
    """Add research columns to ``events`` on existing databases (idempotent)."""
    info = conn.execute("PRAGMA table_info(events)").fetchall()
    names = {str(row[1]) for row in info}
    alters: list[tuple[str, str]] = [
        ("true_label", "ALTER TABLE events ADD COLUMN true_label TEXT"),
        ("ai_prediction", "ALTER TABLE events ADD COLUMN ai_prediction TEXT"),
        ("rule_prediction", "ALTER TABLE events ADD COLUMN rule_prediction TEXT"),
        ("correction_flag", "ALTER TABLE events ADD COLUMN correction_flag INTEGER DEFAULT 0"),
    ]
    for col, ddl in alters:
        if col not in names:
            conn.execute(ddl)


def _ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def init_db(path: Optional[str] = None) -> None:
    db_path = path or get_settings().database_path
    with _init_lock:
        _ensure_parent(db_path)
        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(SCHEMA)
            _migrate_audit_entries_remove_fk(conn)
            _migrate_event_research_columns(conn)
            conn.commit()
        finally:
            conn.close()


@contextmanager
def get_connection(
    path: Optional[str] = None, *, writable: bool = True
) -> Generator[sqlite3.Connection, None, None]:
    db_path = path or get_settings().database_path
    _ensure_parent(db_path)
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON;")
        if writable:
            conn.execute("PRAGMA journal_mode=WAL;")
        yield conn
        if writable:
            conn.commit()
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}
