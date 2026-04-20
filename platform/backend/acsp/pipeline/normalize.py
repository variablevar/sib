from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from dateutil import parser as date_parser

from acsp.schemas import CoreEventFields, Severity


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: Any) -> str:
    if value is None:
        return _now_iso()
    if isinstance(value, (int, float)):
        # microseconds epoch
        try:
            return datetime.fromtimestamp(float(value) / 1_000_000_000, tz=timezone.utc).isoformat()
        except Exception:
            return _now_iso()
    text = str(value)
    try:
        return date_parser.isoparse(text).astimezone(timezone.utc).isoformat()
    except Exception:
        return _now_iso()


def _coerce_severity(value: str | None) -> Severity:
    v = (value or "info").lower()
    mapping: dict[str, Severity] = {
        "emergency": "critical",
        "alert": "critical",
        "critical": "critical",
        "error": "high",
        "warning": "medium",
        "notice": "low",
        "informational": "low",
        "info": "low",
        "debug": "info",
    }
    return mapping.get(v, "info")


def _extract_output_fields(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("output_fields")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _container_from_fields(fields: dict[str, Any], payload: dict[str, Any]) -> str:
    for key in (
        "container.id",
        "container_id",
        "k8s.pod.name",
        "k8s.ns.name",
    ):
        val = fields.get(key)
        if val:
            return str(val)
    cont = payload.get("container")
    if isinstance(cont, dict) and cont.get("id"):
        return str(cont["id"])
    return ""


def _host(fields: dict[str, Any], payload: dict[str, Any]) -> str:
    for key in ("hostname", "fd.sip", "evt.hostname"):
        if fields.get(key):
            return str(fields[key])
    return str(payload.get("hostname") or payload.get("host") or "")


def _proc(fields: dict[str, Any]) -> str:
    for key in ("proc.name", "proc.pname", "proc.exepath"):
        if fields.get(key):
            return str(fields[key])
    return ""


def unwrap_falco_event(body: Any) -> dict[str, Any]:
    """Normalize various Falcosidekick / Falco JSON shapes to a single dict."""
    if isinstance(body, list) and body:
        body = body[0]
    if not isinstance(body, dict):
        return {}
    if "event" in body and isinstance(body["event"], dict):
        inner = body["event"]
        merged = {**body, **inner}
        merged.pop("event", None)
        return merged
    return body


def normalize_sidekick_payload(payload: dict[str, Any]) -> tuple[CoreEventFields, dict[str, Any]]:
    """
    Map Falco JSON into the unified core schema.

    Returns (core_fields, metadata dict for storage / AI context).
    """
    p = unwrap_falco_event(payload)
    fields = _extract_output_fields(p)

    rule = str(p.get("rule") or p.get("ruleName") or "unknown_rule")
    output = str(p.get("output") or p.get("message") or "")
    priority = str(p.get("priority") or p.get("Priority") or "informational")

    ts = _parse_time(p.get("time") or p.get("evt.time") or p.get("timestamp"))

    core = CoreEventFields(
        timestamp=ts,
        source=str(p.get("source") or "falco"),
        severity=_coerce_severity(priority),
        event_type=rule,
        container_id=_container_from_fields(fields, p),
        raw_log=output,
    )

    meta = {
        "tags": p.get("tags") or [],
        "hostname": _host(fields, p),
        "proc_name": _proc(fields),
        "output_fields": fields,
        "falco_priority": priority,
    }
    return core, meta
