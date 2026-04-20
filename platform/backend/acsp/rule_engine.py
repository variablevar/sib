from __future__ import annotations

import re
from typing import Any

from acsp.schemas import CoreEventFields, RuleEngineResult, Severity

_HIGH_PATTERNS = (
    r"reverse.?shell",
    r"cryptominer",
    r"miner",
    r"shadow",
    r"/etc/shadow",
    r"privilege.?escalation",
    r"container.?escape",
    r"release_agent",
    r"ptrace",
)

_MEDIUM_PATTERNS = (
    r"shell.?(spawn|in).?container",
    r"terminal.?shell",
    r"unexpected.?network",
    r"ssh",
    r"kubectl",
    r"packet.?socket",
)

_SAFE_HINTS = (
    r"known.?shell.?parent",
    r"user.?known",
    r"expected",
)


def _match_any(text: str, patterns: tuple[str, ...]) -> list[str]:
    hits: list[str] = []
    lowered = text.lower()
    for p in patterns:
        if re.search(p, lowered, re.IGNORECASE):
            hits.append(p)
    return hits


def _priority_to_severity(priority: str) -> Severity:
    p = (priority or "").lower()
    if p in ("emergency", "alert", "critical"):
        return "critical"
    if p in ("error",):
        return "high"
    if p in ("warning",):
        return "medium"
    if p in ("notice", "informational", "info"):
        return "low"
    return "info"


def _rank(sev: Severity) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[sev]


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if _rank(a) >= _rank(b) else b


def evaluate_rules(
    falco_payload: dict[str, Any],
    core: CoreEventFields,
) -> RuleEngineResult:
    """Deterministic baseline logic — comparison anchor for AI / LLM extensions."""
    matched: list[str] = []
    signals: dict[str, Any] = {}

    priority = str(falco_payload.get("priority") or "")
    baseline = _priority_to_severity(priority)
    matched.append(f"priority_map:{priority}->{baseline}")

    haystack = f"{core.event_type}\n{core.raw_log}".lower()
    high_hits = _match_any(haystack, _HIGH_PATTERNS)
    med_hits = _match_any(haystack, _MEDIUM_PATTERNS)
    safe_hits = _match_any(haystack, _SAFE_HINTS)

    if high_hits:
        baseline = _max_severity(baseline, "high")
        matched.append("pattern:high_threat")
        signals["high_patterns"] = high_hits
    if med_hits:
        baseline = _max_severity(baseline, "medium")
        matched.append("pattern:medium_threat")
        signals["medium_patterns"] = med_hits
    if safe_hits and not high_hits:
        # downgrade one notch if only benign hints (never below info)
        if baseline == "medium":
            baseline = "low"
        elif baseline == "low":
            baseline = "info"
        matched.append("pattern:benign_hint")
        signals["safe_hints"] = safe_hits

    tags = falco_payload.get("tags") or []
    if isinstance(tags, list) and tags:
        signals["tags"] = tags[:20]

    return RuleEngineResult(
        baseline_severity=baseline,
        matched_rules=matched,
        signals=signals,
    )
