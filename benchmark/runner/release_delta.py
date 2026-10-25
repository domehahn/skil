#!/usr/bin/env python3
"""Compute release detection deltas without importing third-party fixtures."""

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    detected: bool


def release_delta(old: Iterable[CaseResult], new: Iterable[CaseResult], skil: Iterable[CaseResult]) -> dict:
    old_map = {item.case_id: item.detected for item in old}
    new_map = {item.case_id: item.detected for item in new}
    skil_map = {item.case_id: item.detected for item in skil}
    case_ids = sorted(set(old_map) | set(new_map) | set(skil_map))
    if set(old_map) != set(new_map) or set(old_map) != set(skil_map):
        return {"complete": False, "limitation": "case identity sets differ", "cases": case_ids}
    newly_detected = [case for case in case_ids if not old_map[case] and new_map[case]]
    corrected = [case for case in case_ids if old_map[case] and not new_map[case]]
    skil_gaps = [case for case in newly_detected if not skil_map[case]]
    return {
        "complete": True,
        "newly_detected": newly_detected,
        "corrected_or_regressed": corrected,
        "skil_gaps": skil_gaps,
        "skil_covers_new_delta": not skil_gaps,
    }

