from __future__ import annotations

import json
from typing import Any, Optional

from acsp.db import get_connection


def get_event(event_id: str, *, db_path: str | None = None) -> Optional[dict[str, Any]]:
    with get_connection(db_path, writable=False) as conn:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        if not row:
            return None
        payload = json.loads(row["payload_json"])
        keys = row.keys()
        for k in ("true_label", "ai_prediction", "rule_prediction", "correction_flag"):
            if k in keys:
                payload[k] = row[k]
        label = conn.execute(
            "SELECT is_true_positive, notes FROM evaluation_labels WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if label:
            payload["evaluation"] = {
                "is_true_positive": (None if label["is_true_positive"] is None else bool(label["is_true_positive"])),
                "notes": label["notes"] or "",
            }
        return payload


def list_events(
    *,
    severity: Optional[str] = None,
    container: Optional[str] = None,
    q: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db_path: str | None = None,
) -> list[dict[str, Any]]:
    clauses: list[str] = ["1=1"]
    params: list[Any] = []

    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if container:
        clauses.append("container_id LIKE ?")
        params.append(f"%{container}%")
    if time_from:
        clauses.append("timestamp >= ?")
        params.append(time_from)
    if time_to:
        clauses.append("timestamp <= ?")
        params.append(time_to)
    if q:
        clauses.append("(event_type LIKE ? OR raw_log LIKE ? OR container_id LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like])

    sql = f"""
        SELECT id, timestamp, source, severity, event_type, container_id, raw_log, payload_json, created_at
        FROM events
        WHERE {' AND '.join(clauses)}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    out: list[dict[str, Any]] = []
    with get_connection(db_path, writable=False) as conn:
        for row in conn.execute(sql, params):
            item = json.loads(row["payload_json"])
            out.append(item)
    return out


def stats_summary(*, db_path: str | None = None) -> dict[str, Any]:
    with get_connection(db_path, writable=False) as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM events GROUP BY severity"
        ).fetchall()
        by_sev = {str(r["severity"]): int(r["c"]) for r in sev_rows}
        last = conn.execute(
            "SELECT timestamp FROM events ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
    return {
        "total_events": total,
        "by_severity": {k: by_sev.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "last_event_at": last["timestamp"] if last else None,
    }


def tail_raw_logs(limit: int = 200, *, db_path: str | None = None) -> list[dict[str, Any]]:
    with get_connection(db_path, writable=False) as conn:
        cur = conn.execute(
            "SELECT id, event_id, line, created_at FROM raw_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]


def tail_audit(event_id: str | None, limit: int, *, db_path: str | None = None) -> list[dict[str, Any]]:
    clauses = []
    params: list[Any] = []
    if event_id:
        clauses.append("event_id = ?")
        params.append(event_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    with get_connection(db_path, writable=False) as conn:
        cur = conn.execute(
            f"""
            SELECT id, event_id, stage, decision, detail_json, created_at
            FROM audit_entries
            {where}
            ORDER BY id DESC
            LIMIT ?
            """,
            params,
        )
        rows = []
        for r in cur.fetchall():
            rows.append(
                {
                    "id": r["id"],
                    "event_id": r["event_id"],
                    "stage": r["stage"],
                    "decision": r["decision"],
                    "detail": json.loads(r["detail_json"] or "{}"),
                    "created_at": r["created_at"],
                }
            )
        return rows
