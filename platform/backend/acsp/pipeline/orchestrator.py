from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

import httpx

from acsp.ai.mock_engine import MockAIEngine
from acsp.audit import append_raw_log, log_decision
from acsp.db import get_connection
from acsp.pipeline.normalize import normalize_sidekick_payload
from acsp.research.feedback_loop import get_score_adjustment, record_feedback
from acsp.rule_engine import evaluate_rules
from acsp.schemas import AIAnalysisResult, EnrichedSecurityEvent, RuleEngineResult, Severity
from acsp.settings import get_settings


def _severity_to_binary(sev: Severity) -> Literal["malicious", "benign"]:
    return "malicious" if sev in ("critical", "high", "medium") else "benign"


def _ai_score_to_binary(ai: AIAnalysisResult) -> Literal["malicious", "benign"]:
    return "malicious" if ai.severity_score >= 50 else "benign"


def _merge_severity(rule: RuleEngineResult, ai: AIAnalysisResult) -> Severity:
    """Combine baseline + AI score into unified severity (logged for research)."""
    score = ai.severity_score
    baseline: Severity = rule.baseline_severity
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return baseline


def process_falco_payload(
    raw_payload: dict[str, Any],
    *,
    db_path: str | None = None,
    notify: bool = True,
    ground_truth: Optional[Literal["malicious", "benign"]] = None,
) -> EnrichedSecurityEvent:
    """
    Full pipeline: ingestion → normalization → rule engine → mock AI → storage → audit → feedback_loop.

    Audit stages: ingest, normalize, rule_engine, ai, storage.
    """
    settings = get_settings()
    event_id = str(uuid.uuid4())
    raw_json = json.dumps(raw_payload, default=str)[:200000]

    log_decision(event_id, "ingest", "received", {"bytes": len(raw_json)}, db_path=db_path)
    append_raw_log(raw_json, event_id, db_path=db_path)

    core, meta = normalize_sidekick_payload(raw_payload)
    log_decision(
        event_id,
        "normalize",
        "mapped_core_fields",
        {"event_type": core.event_type, "severity": core.severity},
        db_path=db_path,
    )

    rule_result = evaluate_rules(raw_payload, core)
    log_decision(
        event_id,
        "rule_engine",
        "baseline_evaluated",
        rule_result.model_dump(),
        db_path=db_path,
    )

    engine = MockAIEngine()
    score_adj = get_score_adjustment(db_path=db_path)
    ai_result = engine.analyze(
        core,
        rule_result,
        {**raw_payload, **meta, "_acsp_score_adjustment": score_adj},
    )
    log_decision(
        event_id,
        "ai",
        f"engine={engine.name}",
        ai_result.model_dump(),
        db_path=db_path,
    )

    unified_sev = _merge_severity(rule_result, ai_result)
    rule_prediction = _severity_to_binary(rule_result.baseline_severity)
    ai_prediction = _ai_score_to_binary(ai_result)

    enriched = EnrichedSecurityEvent(
        id=event_id,
        core=core.model_copy(update={"severity": unified_sev}),
        rule_engine=rule_result,
        ai=ai_result,
        falco_priority=meta.get("falco_priority", ""),
        host=str(meta.get("hostname", "")),
        proc_name=str(meta.get("proc_name", "")),
        raw_sidekick=raw_payload,
    )

    now = datetime.now(timezone.utc).isoformat()
    payload_blob = enriched.model_dump(mode="json")
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO events (
                id, timestamp, source, severity, event_type, container_id, raw_log, payload_json, created_at,
                true_label, ai_prediction, rule_prediction, correction_flag
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                event_id,
                enriched.core.timestamp,
                enriched.core.source,
                enriched.core.severity,
                enriched.core.event_type,
                enriched.core.container_id,
                enriched.core.raw_log,
                json.dumps(payload_blob, default=str),
                now,
                ground_truth,
                ai_prediction,
                rule_prediction,
            ),
        )

    log_decision(event_id, "storage", "persisted", {"table": "events"}, db_path=db_path)

    record_feedback(
        event_id,
        ground_truth,
        ai_prediction,
        rule_prediction,
        correction_flag=0,
        db_path=db_path,
    )

    if notify:
        try:
            httpx.post(
                f"{settings.api_gateway_url.rstrip('/')}/internal/broadcast",
                json={"event_id": event_id},
                headers={"X-Internal-Secret": settings.internal_secret},
                timeout=2.0,
            )
        except Exception:
            # Polling still works if API is momentarily down
            log_decision(event_id, "notify", "broadcast_skipped", {}, db_path=db_path)

    return enriched
