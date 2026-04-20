from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]


class CoreEventFields(BaseModel):
    """Canonical event shape used across ingestion, storage, and API."""

    timestamp: str = Field(..., description="ISO-8601 timestamp")
    source: str = Field(..., description="Origin system, e.g. falco")
    severity: Severity = Field(..., description="Unified severity bucket")
    event_type: str = Field(..., description="Logical event type / rule name")
    container_id: str = Field(default="", description="Container or workload identifier")
    raw_log: str = Field(default="", description="Primary human-readable log line")


class RuleEngineResult(BaseModel):
    baseline_severity: Severity
    matched_rules: list[str] = Field(default_factory=list)
    signals: dict[str, Any] = Field(default_factory=dict)


class AIAnalysisResult(BaseModel):
    severity_score: int = Field(..., ge=0, le=100, description="0–100 risk score")
    explanation: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    mitigations: list[str] = Field(
        default_factory=list,
        description="Analyst-only suggested actions (guidance text; no automated enforcement).",
    )


class EnrichedSecurityEvent(BaseModel):
    """Full document stored and returned by the API (extends core schema)."""

    id: str
    core: CoreEventFields
    rule_engine: RuleEngineResult
    ai: AIAnalysisResult
    falco_priority: str = ""
    host: str = ""
    proc_name: str = ""
    raw_sidekick: dict[str, Any] = Field(default_factory=dict)


class AuditEntry(BaseModel):
    id: int
    event_id: str
    stage: str
    decision: str
    detail: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class EventLabel(BaseModel):
    """Manual ground truth for dissertation evaluation."""

    is_true_positive: Optional[bool] = None
    notes: str = ""
