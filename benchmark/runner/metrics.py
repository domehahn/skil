"""TP/FP/TN/FN and derived metrics for one tool's results over a fixture set.

Deliberately independent of any specific tool's internal rule/category
vocabulary: the only inputs are a ground-truth boolean per fixture and a
detected boolean per fixture.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    errors: int = 0  # detected is None: the tool failed to produce a parseable result

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def false_positive_rate(self) -> float | None:
        denom = self.fp + self.tn
        return self.fp / denom if denom else None

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "errors": self.errors,
            "total": self.total,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
        }


def confusion_for(results: list[tuple[bool, bool | None]]) -> Confusion:
    """results: list of (ground_truth_malicious, tool_detected)."""
    c = Confusion()
    for malicious, detected in results:
        if detected is None:
            c.errors += 1
            continue
        if malicious and detected:
            c.tp += 1
        elif malicious and not detected:
            c.fn += 1
        elif not malicious and detected:
            c.fp += 1
        else:
            c.tn += 1
    return c
