from __future__ import annotations

import re
from typing import Any

from acsp.ai.analyst_guidance import suggested_mitigations
from acsp.schemas import AIAnalysisResult, CoreEventFields, RuleEngineResult, Severity

_SUSPICIOUS = (
    "shell",
    "bash",
    "sh ",
    "/bin/sh",
    "curl ",
    "wget ",
    "python -c",
    "base64",
    "nc ",
    "netcat",
    "chmod 4777",
    "mknod",
    "insmod",
    "bpf",
    "packet_socket",
)

_SAFE = (
    "expected",
    "known",
    "healthcheck",
    "probe",
)


def _rank_severity(s: Severity) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[s]


class MockAIEngine:
    """Local-only heuristic engine — structured like an LLM adapter for later replacement."""

    name = "mock_heuristic_v1"

    def analyze(
        self,
        core: CoreEventFields,
        rule_engine: RuleEngineResult,
        raw_context: dict[str, Any],
    ) -> AIAnalysisResult:
        text = f"{core.event_type}\n{core.raw_log}".lower()
        score = 15 + _rank_severity(rule_engine.baseline_severity) * 18
        reasons: list[str] = []

        kw_hits = [kw for kw in _SUSPICIOUS if kw in text]
        if kw_hits:
            score += min(40, 6 * len(kw_hits))
            reasons.append(f"Suspicious keywords ({len(kw_hits)} hits): {', '.join(kw_hits[:6])}")

        safe_hits = [kw for kw in _SAFE if kw in text]
        if safe_hits:
            score -= 12
            reasons.append(f"Benign context hints: {', '.join(safe_hits[:4])}")

        if rule_engine.signals.get("high_patterns"):
            score += 25
            reasons.append("Rule engine marked high-impact patterns.")

        # Falco tags sometimes encode MITRE / maturity
        tags = raw_context.get("tags") or []
        if isinstance(tags, list):
            tag_text = " ".join(str(t) for t in tags).lower()
            if re.search(r"mitre", tag_text):
                score += 5
                reasons.append("MITRE-related tags increase analyst interest.")

        adj = float(raw_context.get("_acsp_score_adjustment") or 0.0)
        if adj:
            score += adj
            reasons.append(f"Feedback score adjustment ({adj:+.1f}).")

        score = max(0, min(100, int(round(score))))

        if score >= 75:
            bucket = "likely malicious / urgent triage"
        elif score >= 50:
            bucket = "suspicious — validate against change management"
        elif score >= 30:
            bucket = "noisy but worth a quick glance"
        else:
            bucket = "likely benign automation"

        confidence = 0.55
        if len(reasons) >= 2:
            confidence += 0.15
        if kw_hits and not safe_hits:
            confidence += 0.15
        confidence = min(0.95, confidence)

        explanation = (
            f"[{self.name}] {bucket}. " + (" ".join(reasons) if reasons else "No strong keyword signals.")
        )

        mits = suggested_mitigations(core, rule_engine, severity_score=score)

        return AIAnalysisResult(
            severity_score=score,
            explanation=explanation,
            confidence=round(confidence, 3),
            mitigations=mits,
        )
