"""
Analyst-only response layer: deterministic mitigation / triage hints (no automation).

Suitable for thesis framing: AI supports human decision-making, not autonomous enforcement.
"""

from __future__ import annotations

from acsp.schemas import CoreEventFields, RuleEngineResult


def suggested_mitigations(
    core: CoreEventFields,
    rule_engine: RuleEngineResult,
    *,
    severity_score: int,
) -> list[str]:
    """Return short, actionable analyst checklist items (text only)."""
    text = f"{core.event_type}\n{core.raw_log}".lower()
    out: list[str] = []

    def add(s: str) -> None:
        if s not in out:
            out.append(s)

    if any(x in text for x in ("reverse", "tcp/", "/dev/tcp", "bash -i", "nc ", "netcat")):
        add("Isolate the workload in a sandbox or cordon node until intent is confirmed.")
        add("Capture full process tree, network flows, and container image digest for evidence.")
        add("Rotate credentials that may have been exposed on the same host or namespace.")

    if any(x in text for x in ("/etc/shadow", "credential", "ssh", "kubeconfig")):
        add("Verify whether access was expected (break-glass, backup job) via change records.")
        add("Review IAM / RBAC bindings for the identity that ran the process.")

    if any(x in text for x in ("sudo", "chmod 4777", "setuid", "privilege")):
        add("Compare binary hash against golden image; check for drift or supply-chain compromise.")
        add("Escalate to platform owner if this is not an approved maintenance window.")

    if any(x in text for x in ("xmrig", "stratum", "miner", "cryptominer", "mining")):
        add("Quarantine candidate workload from outbound internet except approved registries.")
        add("Scan sibling containers on the host for the same binary or C2 patterns.")

    if rule_engine.signals.get("high_patterns"):
        add("Map to MITRE ATT&CK techniques referenced in tags and update detection coverage notes.")

    if severity_score >= 60:
        add("Open or update an incident ticket with timeline, owner, and blast-radius estimate.")
    elif severity_score >= 40:
        add("Schedule analyst review within SLA; correlate with deployment and config changes.")

    if core.container_id:
        add(f"Inspect container {core.container_id[:48]}{'…' if len(core.container_id) > 48 else ''} logs and prior alerts.")

    if not out:
        add("No high-urgency pattern bundle matched; treat as routine triage unless context says otherwise.")
        add("Confirm workload owner and document disposition (true/false positive) for metrics.")

    return out[:8]
