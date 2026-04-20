"""
Evaluation metrics from SQLite only — rule_engine vs ground truth and ai_engine vs ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from acsp.db import get_connection


@dataclass(frozen=True)
class BinaryMetrics:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def precision(self) -> Optional[float]:
        d = self.tp + self.fp
        return self.tp / d if d else None

    @property
    def recall(self) -> Optional[float]:
        d = self.tp + self.fn
        return self.tp / d if d else None

    @property
    def accuracy(self) -> Optional[float]:
        d = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / d if d else None

    @property
    def false_positive_rate(self) -> Optional[float]:
        d = self.fp + self.tn
        return self.fp / d if d else None

    @property
    def false_negative_rate(self) -> Optional[float]:
        d = self.fn + self.tp
        return self.fn / d if d else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "true_positive": self.tp,
            "false_positive": self.fp,
            "true_negative": self.tn,
            "false_negative": self.fn,
            "precision": self.precision,
            "recall": self.recall,
            "accuracy": self.accuracy,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
        }


def _confusion(truth: str, pred: str) -> tuple[int, int, int, int]:
    """Single row contribution: malicious positive class."""
    t = truth == "malicious"
    p = pred == "malicious"
    if t and p:
        return 1, 0, 0, 0
    if t and not p:
        return 0, 0, 0, 1
    if not t and p:
        return 0, 1, 0, 0
    return 0, 0, 1, 0


def _sum_metrics(rows: list[tuple[str, str]]) -> BinaryMetrics:
    tp = fp = tn = fn = 0
    for truth, pred in rows:
        if truth not in ("malicious", "benign") or pred not in ("malicious", "benign"):
            continue
        a, b, c, d = _confusion(truth, pred)
        tp += a
        fp += b
        tn += c
        fn += d
    return BinaryMetrics(tp=tp, fp=fp, tn=tn, fn=fn)


def compute_full_metrics(*, db_path: str | None = None) -> dict[str, Any]:
    """
    Load rows with ``true_label`` and both predictions populated; compute confusion metrics.
    """
    sql = """
        SELECT true_label, ai_prediction, rule_prediction
        FROM events
        WHERE true_label IS NOT NULL
          AND ai_prediction IS NOT NULL
          AND rule_prediction IS NOT NULL
    """
    with get_connection(db_path, writable=False) as conn:
        cur = conn.execute(sql)
        rows_ai: list[tuple[str, str]] = []
        rows_rule: list[tuple[str, str]] = []
        for r in cur.fetchall():
            truth = str(r["true_label"])
            rows_ai.append((truth, str(r["ai_prediction"])))
            rows_rule.append((truth, str(r["rule_prediction"])))

    ai_m = _sum_metrics(rows_ai)
    rule_m = _sum_metrics(rows_rule)
    n = len(rows_ai)

    return {
        "labeled_events": n,
        "rule_engine_vs_ground_truth": rule_m.as_dict(),
        "ai_engine_vs_ground_truth": ai_m.as_dict(),
    }


