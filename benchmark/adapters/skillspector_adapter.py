"""Adapter for the pinned OSS reference scanner (see benchmark/README.md for
which product and why it's named here, unlike the rest of this repository).

Verified against a real local install (v2.9.6) before being written, not
transcribed from documentation alone — that install's JSON schema differs
from what its own docs/DEVELOPMENT.md describes, which is exactly the kind
of drift a benchmark run naturally catches and this comment records for the
next person who touches this adapter.

Normalizes `<tool> scan <artifact> --no-llm --format json --output <file>`
into the same {detected, ...} shape skil_adapter.py produces. "detected" =
risk_assessment.recommendation != "SAFE" (CAUTION or DO_NOT_INSTALL both
count — the tool's own weaker-than-block-but-still-flagged state).

--no-llm is required for this benchmark's v1 scope: Track A (deterministic,
offline) only. See benchmark/README.md.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def identity(binary: str) -> dict[str, str]:
    result = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True)
    return {"tool": binary, "version": result.stdout.strip()}


def scan(binary: str, artifact_dir: Path) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = Path(tmp.name)
    try:
        subprocess.run(
            [binary, "scan", str(artifact_dir), "--no-llm", "--format", "json", "--output", str(output_path)],
            capture_output=True,
            text=True,
        )
        try:
            report = json.loads(output_path.read_text())
        except (json.JSONDecodeError, FileNotFoundError) as exc:
            return {"detected": None, "error": f"could not parse scanner output: {exc}"}
    finally:
        output_path.unlink(missing_ok=True)

    risk = report.get("risk_assessment", {})
    issues = report.get("issues", [])
    return {
        "detected": risk.get("recommendation") != "SAFE",
        "recommendation": risk.get("recommendation"),
        "risk_score": risk.get("score"),
        "severity": risk.get("severity"),
        "rule_ids": sorted({issue.get("id") for issue in issues if issue.get("id")}),
    }
