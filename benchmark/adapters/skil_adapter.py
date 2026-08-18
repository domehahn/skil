"""Adapter for skil itself.

Normalizes `skil scan <artifact> --format json` output into the shared
benchmark decision shape: did the tool flag this artifact as something a
reasonable operator should not install as-is?

skil's own verdict enum (CLEAR/REVIEW/BLOCK) already encodes exactly that
decision, so "detected" = verdict != CLEAR. REVIEW counts as detected: a
verdict that stops short of an outright block but still surfaces the
artifact for human attention is not a miss.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


def identity(binary: str) -> dict[str, str]:
    result = subprocess.run([binary, "version"], capture_output=True, text=True, check=True)
    return {"tool": "skil", "version": result.stdout.strip()}


def scan(binary: str, artifact_dir: Path) -> dict[str, Any]:
    result = subprocess.run(
        [binary, "scan", str(artifact_dir), "--format", "json"],
        capture_output=True,
        text=True,
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return {
            "detected": None,
            "error": f"could not parse skil output: {exc}",
            "raw_stderr": result.stderr[-2000:],
        }
    return {
        "detected": report.get("verdict") != "CLEAR",
        "verdict": report.get("verdict"),
        "risk_score": report.get("risk_score"),
        "maximum_severity": report.get("maximum_severity"),
        "rule_ids": sorted({f["rule_id"] for f in report.get("findings", [])}),
    }
