from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from acsp.db import get_connection


def log_decision(
    event_id: str,
    stage: str,
    decision: str,
    detail: Optional[dict[str, Any]] = None,
    *,
    db_path: str | None = None,
) -> None:
    """Append an audit record for pipeline or API decisions."""
    now = datetime.now(timezone.utc).isoformat()
    detail_json = json.dumps(detail or {}, default=str)
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO audit_entries (event_id, stage, decision, detail_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event_id, stage, decision, detail_json, now),
        )


def append_raw_log(
    line: str,
    event_id: str | None = None,
    *,
    db_path: str | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO raw_logs (event_id, line, created_at) VALUES (?, ?, ?)",
            (event_id, line[:65535], now),
        )
