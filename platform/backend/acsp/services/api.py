"""API gateway — read models, research metrics, WebSocket fan-out, internal hooks."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from acsp.audit import log_decision
from acsp.db import get_connection, init_db
from acsp.pipeline.orchestrator import process_falco_payload
from acsp.repository import (
    get_event,
    list_events,
    stats_summary,
    tail_audit,
    tail_raw_logs,
)
from acsp.research.feedback_loop import error_pattern_summary, recompute_patterns
from acsp.research.metrics import compute_full_metrics
from acsp.simulator.attack_generator import generate_n_events
from acsp.settings import Settings, get_settings

logger = logging.getLogger("acsp.api")
logging.basicConfig(level=logging.INFO)


class ConnectionHub:
    def __init__(self) -> None:
        self.clients: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.clients.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.clients:
            self.clients.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for client in self.clients:
            try:
                await client.send_json(message)
            except Exception:
                dead.append(client)
        for c in dead:
            self.disconnect(c)


hub = ConnectionHub()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="ACSP API Gateway",
    version="0.1.0",
    description="Local AI Cloud Security Platform — dissertation / research API.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in get_settings().cors_origins.split(",") if o.strip()],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def settings_dep() -> Settings:
    return get_settings()


def _flatten_research_metrics(out: dict[str, Any]) -> dict[str, Any]:
    ai = out.get("ai_engine_vs_ground_truth") or {}
    out["labeled_count"] = out.get("labeled_events", 0)
    out["precision"] = ai.get("precision")
    out["recall"] = ai.get("recall")
    out["false_positive_rate"] = ai.get("false_positive_rate")
    out["false_negative_rate"] = ai.get("false_negative_rate")
    out["accuracy"] = ai.get("accuracy")
    out["true_positive"] = ai.get("true_positive")
    out["false_positive"] = ai.get("false_positive")
    out["true_negative"] = ai.get("true_negative")
    out["false_negative"] = ai.get("false_negative")
    return out


class BroadcastBody(BaseModel):
    event_id: str


class LabelBody(BaseModel):
    is_true_positive: Optional[bool] = None
    notes: str = ""


class DemoEventBody(BaseModel):
    rule: str = Field(default="User Exec from suspicious shell")
    output: str = Field(default="bash launched curl to unknown host (demo)")
    priority: str = Field(default="warning")


class DemoGenerateBody(BaseModel):
    n: int = Field(50, ge=1, le=5000)
    attack_ratio: float = Field(0.3, ge=0.0, le=1.0)


@app.get("/api/v1/health")
def health(settings: Settings = Depends(settings_dep)) -> dict[str, Any]:
    db_ok = False
    try:
        with get_connection(settings.database_path, writable=False) as conn:
            conn.execute("SELECT 1")
        db_ok = True
    except Exception as exc:
        logger.warning("db health failed: %s", exc)
    return {
        "status": "ok" if db_ok else "degraded",
        "components": {
            "sqlite": "up" if db_ok else "down",
            "api": "up",
            "websocket_clients": len(hub.clients),
        },
    }


@app.get("/api/v1/stats/summary")
def api_stats(settings: Settings = Depends(settings_dep)) -> dict[str, Any]:
    return stats_summary(db_path=settings.database_path)


@app.get("/api/v1/stats/timeline")
def api_timeline(
    settings: Settings = Depends(settings_dep),
    limit_buckets: int = Query(48, ge=1, le=500),
) -> list[dict[str, Any]]:
    """Aggregated counts for charts (bucket = hour prefix from ISO timestamp)."""
    with get_connection(settings.database_path, writable=False) as conn:
        rows = conn.execute(
            """
            SELECT substr(timestamp, 1, 13) AS bucket, severity, COUNT(*) AS c
            FROM events
            GROUP BY bucket, severity
            ORDER BY bucket DESC
            LIMIT ?
            """,
            (limit_buckets * 5,),
        ).fetchall()
    # collapse ordering ascending for charts
    out = [{"bucket": r["bucket"], "severity": r["severity"], "count": int(r["c"])} for r in rows]
    out.sort(key=lambda x: x["bucket"])
    return out[-limit_buckets * 5 :]


@app.get("/api/v1/events")
def api_list_events(
    settings: Settings = Depends(settings_dep),
    severity: Optional[str] = None,
    container: Optional[str] = None,
    q: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    return list_events(
        severity=severity,
        container=container,
        q=q,
        time_from=time_from,
        time_to=time_to,
        limit=limit,
        offset=offset,
        db_path=settings.database_path,
    )


@app.get("/api/v1/events/{event_id}")
def api_get_event(event_id: str, settings: Settings = Depends(settings_dep)) -> dict[str, Any]:
    row = get_event(event_id, db_path=settings.database_path)
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    return row


@app.get("/api/v1/audit")
def api_audit(
    settings: Settings = Depends(settings_dep),
    event_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return tail_audit(event_id, limit, db_path=settings.database_path)


@app.get("/api/v1/logs/raw")
def api_raw_logs(
    settings: Settings = Depends(settings_dep),
    limit: int = Query(200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    return tail_raw_logs(limit, db_path=settings.database_path)


@app.get("/api/v1/research/metrics")
def api_research_metrics(settings: Settings = Depends(settings_dep)) -> dict[str, Any]:
    out = compute_full_metrics(db_path=settings.database_path)
    out["error_patterns_top"] = error_pattern_summary(db_path=settings.database_path)[:12]
    return _flatten_research_metrics(out)


@app.post("/api/v1/research/recompute")
def api_research_recompute(settings: Settings = Depends(settings_dep)) -> dict[str, Any]:
    """Rebuild mismatch pattern aggregates and return fresh metrics from SQLite."""
    pr = recompute_patterns(db_path=settings.database_path)
    metrics = compute_full_metrics(db_path=settings.database_path)
    metrics["patterns_rebuilt"] = pr.get("patterns_rebuilt", 0)
    metrics["error_patterns_top"] = error_pattern_summary(db_path=settings.database_path)[:12]
    return _flatten_research_metrics(metrics)


@app.get("/api/v1/architecture")
def api_architecture() -> dict[str, Any]:
    """Static pipeline description for the System Architecture page."""
    return {
        "title": "ACSP local pipeline",
        "stages": [
            {"id": "falco", "label": "Falco", "description": "eBPF runtime security engine"},
            {"id": "sidekick", "label": "Falcosidekick", "description": "Fan-out; webhook to processor"},
            {"id": "ingest", "label": "Ingestion", "description": "Validate JSON, append raw audit log"},
            {"id": "normalize", "label": "Normalization", "description": "Map to unified core event schema"},
            {"id": "rules", "label": "Rule engine", "description": "Deterministic baseline severity + patterns"},
            {"id": "ai", "label": "AI module", "description": "Pluggable engine (mock heuristics today)"},
            {"id": "store", "label": "SQLite", "description": "Events, audit trail, evaluation labels"},
            {"id": "api", "label": "API + WS", "description": "Gateway for dashboard and research queries"},
        ],
        "edges": [
            ["falco", "sidekick"],
            ["sidekick", "ingest"],
            ["ingest", "normalize"],
            ["normalize", "rules"],
            ["rules", "ai"],
            ["ai", "store"],
            ["store", "api"],
        ],
    }


@app.post("/api/v1/events/{event_id}/label")
def api_label_event(
    event_id: str,
    body: LabelBody,
    settings: Settings = Depends(settings_dep),
) -> dict[str, str]:
    now = datetime.now(timezone.utc).isoformat()
    with get_connection(settings.database_path) as conn:
        exists = conn.execute("SELECT 1 FROM events WHERE id = ?", (event_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="Event not found")
        if body.is_true_positive is None and not body.notes:
            conn.execute("DELETE FROM evaluation_labels WHERE event_id = ?", (event_id,))
            conn.execute(
                "UPDATE events SET true_label = NULL, correction_flag = 0 WHERE id = ?",
                (event_id,),
            )
        else:
            val = None if body.is_true_positive is None else (1 if body.is_true_positive else 0)
            conn.execute(
                """
                INSERT INTO evaluation_labels (event_id, is_true_positive, notes, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                  is_true_positive=excluded.is_true_positive,
                  notes=excluded.notes,
                  updated_at=excluded.updated_at
                """,
                (event_id, val, body.notes, now),
            )
            if body.is_true_positive is not None:
                truth = "malicious" if body.is_true_positive else "benign"
                conn.execute(
                    "UPDATE events SET true_label = ?, correction_flag = 1 WHERE id = ?",
                    (truth, event_id),
                )
    log_decision(event_id, "api", "evaluation_label_updated", body.model_dump(), db_path=settings.database_path)
    return {"status": "ok"}


@app.post("/api/v1/demo/emit")
def api_demo_emit(
    body: DemoEventBody,
    settings: Settings = Depends(settings_dep),
) -> dict[str, str]:
    """Inject a synthetic Falco-shaped event for UI testing without kernel events."""
    fake = {
        "rule": body.rule,
        "output": body.output,
        "priority": body.priority,
        "time": datetime.now(timezone.utc).isoformat(),
        "tags": ["demo", "acsp"],
        "output_fields": {},
    }
    enriched = process_falco_payload(fake, db_path=settings.database_path, notify=True)
    return {"id": enriched.id, "severity": enriched.core.severity}


@app.post("/api/v1/demo/generate")
def api_demo_generate(
    body: DemoGenerateBody,
    settings: Settings = Depends(settings_dep),
) -> dict[str, Any]:
    """Run attack simulator; each event flows through the full pipeline including feedback_loop."""
    pairs = generate_n_events(body.n, body.attack_ratio)
    last_id: str | None = None
    for i, (payload, gt) in enumerate(pairs):
        enriched = process_falco_payload(
            payload,
            db_path=settings.database_path,
            notify=(i == len(pairs) - 1),
            ground_truth=gt,
        )
        last_id = enriched.id
    return {"generated": len(pairs), "last_event_id": last_id}


@app.post("/internal/broadcast")
async def internal_broadcast(
    body: BroadcastBody,
    settings: Settings = Depends(settings_dep),
    x_internal_secret: Optional[str] = Header(default=None, alias="X-Internal-Secret"),
) -> dict[str, str]:
    if (x_internal_secret or "") != settings.internal_secret:
        raise HTTPException(status_code=403, detail="Forbidden")
    event = get_event(body.event_id, db_path=settings.database_path)
    if event:
        await hub.broadcast({"type": "event", "payload": event})
    return {"status": "ok"}


@app.websocket("/api/v1/ws/live")
async def websocket_live(websocket: WebSocket) -> None:
    await hub.connect(websocket)
    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "heartbeat", "ts": datetime.now(timezone.utc).isoformat()})
    except WebSocketDisconnect:
        hub.disconnect(websocket)
    except Exception:
        hub.disconnect(websocket)


def main() -> None:
    import uvicorn

    s = get_settings()
    init_db()
    uvicorn.run(
        "acsp.services.api:app",
        host=s.api_host,
        port=s.api_port,
        reload=False,
    )


if __name__ == "__main__":
    main()
