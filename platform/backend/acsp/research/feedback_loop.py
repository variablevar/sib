"""
Deterministic feedback from labeled outcomes: mismatch logging + tiny score bias for mock AI.

Not ML training — bounded heuristic adjustments only.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from acsp.audit import log_decision
from acsp.db import get_connection

_STATE_ID = 1
_SCORE_MIN, _SCORE_MAX = -15.0, 15.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_weights() -> dict[str, Any]:
    return {"score_adjustment": 0.0}


def ensure_feedback_tables(conn) -> None:
    """Idempotent — used if DB was created before research tables existed."""
    conn.executescript(
        """
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
    )


def get_weights(*, db_path: str | None = None) -> dict[str, Any]:
    with get_connection(db_path) as conn:
        ensure_feedback_tables(conn)
        row = conn.execute("SELECT weights_json FROM feedback_state WHERE id = ?", (_STATE_ID,)).fetchone()
        if not row:
            w = _default_weights()
            conn.execute(
                "INSERT INTO feedback_state (id, weights_json, updated_at) VALUES (?, ?, ?)",
                (_STATE_ID, json.dumps(w), _now()),
            )
            return dict(w)
        return json.loads(row["weights_json"])


def get_score_adjustment(*, db_path: str | None = None) -> float:
    w = get_weights(db_path=db_path)
    adj = float(w.get("score_adjustment", 0.0))
    return max(_SCORE_MIN, min(_SCORE_MAX, adj))


def record_feedback(
    event_id: str,
    true_label: str | None,
    ai_prediction: str | None,
    rule_prediction: str | None,
    correction_flag: int,
    *,
    db_path: str | None = None,
) -> None:
    """
    After storage: compare predictions to ``true_label``, log mismatches, nudge score weights (AI only).

    Skips learning updates when ``correction_flag`` is set or ``true_label`` is missing.
    """
    if not true_label or true_label not in ("malicious", "benign"):
        return
    if correction_flag:
        log_decision(event_id, "feedback_loop", "skipped_correction_flag", {}, db_path=db_path)
        return
    if not ai_prediction or not rule_prediction:
        return

    weights = dict(get_weights(db_path=db_path))
    adj = float(weights.get("score_adjustment", 0.0))

    with get_connection(db_path) as conn:
        ensure_feedback_tables(conn)
        for component, pred in (("ai", ai_prediction), ("rule", rule_prediction)):
            if pred == true_label:
                continue
            conn.execute(
                """
                INSERT INTO feedback_mismatches (event_id, component, true_label, predicted, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_id, component, true_label, pred, _now()),
            )
            key = f"{component}:true={true_label}:pred={pred}"
            conn.execute(
                """
                INSERT INTO feedback_patterns (pattern_key, count, updated_at) VALUES (?, 1, ?)
                ON CONFLICT(pattern_key) DO UPDATE SET count = count + 1, updated_at = excluded.updated_at
                """,
                (key, _now()),
            )

        # Heuristic weight nudge (AI path only): reduce aggression after benign→malicious FP; increase after FN.
        if ai_prediction != true_label:
            if true_label == "benign" and ai_prediction == "malicious":
                adj -= 1.5
            elif true_label == "malicious" and ai_prediction == "benign":
                adj += 1.5
            adj = max(_SCORE_MIN, min(_SCORE_MAX, adj))
            weights["score_adjustment"] = adj
            conn.execute(
                """
                INSERT INTO feedback_state (id, weights_json, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET weights_json = excluded.weights_json, updated_at = excluded.updated_at
                """,
                (_STATE_ID, json.dumps(weights), _now()),
            )

    log_decision(
        event_id,
        "feedback_loop",
        "processed",
        {"ai_prediction": ai_prediction, "rule_prediction": rule_prediction, "true_label": true_label},
        db_path=db_path,
    )


def recompute_patterns(*, db_path: str | None = None) -> dict[str, Any]:
    """Rebuild ``feedback_patterns`` aggregates from ``feedback_mismatches``."""
    with get_connection(db_path) as conn:
        ensure_feedback_tables(conn)
        conn.execute("DELETE FROM feedback_patterns")
        rows = conn.execute(
            """
            SELECT component || ':' || true_label || ':pred=' || predicted AS k, COUNT(*) AS c
            FROM feedback_mismatches
            GROUP BY component, true_label, predicted
            """
        ).fetchall()
        now = _now()
        for r in rows:
            conn.execute(
                "INSERT INTO feedback_patterns (pattern_key, count, updated_at) VALUES (?, ?, ?)",
                (r["k"], int(r["c"]), now),
            )
    return {"patterns_rebuilt": len(rows)}


def error_pattern_summary(*, db_path: str | None = None) -> list[dict[str, Any]]:
    with get_connection(db_path, writable=False) as conn:
        ensure_feedback_tables(conn)
        cur = conn.execute(
            "SELECT pattern_key, count, updated_at FROM feedback_patterns ORDER BY count DESC LIMIT 50"
        )
        return [dict(r) for r in cur.fetchall()]
