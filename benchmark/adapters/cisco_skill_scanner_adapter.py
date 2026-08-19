"""Adapter for a second pinned OSS reference scanner (see benchmark/README.md
for which product and why it's named here, unlike the rest of this
repository).

Verified against a real local install (v2.0.13) before being written, not
transcribed from documentation alone — same discipline as
skillspector_adapter.py.

Normalizes `skill-scanner scan <artifact> --format json --output <file>`
(offline by default — LLM analysis requires the separate, opt-in --use-llm
flag this benchmark's v1 Track A scope deliberately never passes) into the
same {detected, ...} shape the other adapters produce. "detected" = not
is_safe.
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
            [binary, "scan", str(artifact_dir), "--format", "json", "--output", str(output_path)],
            capture_output=True,
            text=True,
        )
        try:
            report = json.loads(output_path.read_text())
        except (json.JSONDecodeError, FileNotFoundError) as exc:
            return {"detected": None, "error": f"could not parse scanner output: {exc}"}
    finally:
        output_path.unlink(missing_ok=True)

    findings = report.get("findings", [])
    return {
        "detected": report.get("is_safe") is False,
        "max_severity": report.get("max_severity"),
        "findings_count": report.get("findings_count"),
        "rule_ids": sorted({f.get("rule_id") for f in findings if f.get("rule_id")}),
    }
