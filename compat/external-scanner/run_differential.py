#!/usr/bin/env python3
"""Differential comparison of skil against an external reference scanner.

For every property in properties.yaml, runs both scanners against the
positive and negative fixture, and reports whether each side detected the
property. This proves (or disproves) property-level parity by executing
both tools, not by asserting it in documentation.

This deliberately does NOT assert finding-count equality or identical rule
IDs between the two tools (see docs/external-scanner-feature-parity.md for
why that would be the wrong model). It asserts: for this property, did each
tool produce *any* finding on the positive fixture, and no finding on the
negative fixture.

Usage:
    python3 run_differential.py \\
        --skil-binary /path/to/skil \\
        --external-cmd "uv run --project /path/to/reference/clone <external-scanner-entry-point>"
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parent


def load_properties() -> list[dict]:
    with open(ROOT / "properties.yaml") as f:
        return yaml.safe_load(f)["properties"]


def run_skil(binary: str, fixture_dir: Path) -> tuple[bool, list[str], str]:
    """Returns (ran_ok, observed_rule_ids, raw_stderr_on_failure)."""
    try:
        proc = subprocess.run(
            [binary, "scan", str(fixture_dir), "--format", "json"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, [], str(exc)
    if proc.returncode not in (0, 1):
        return False, [], proc.stderr[:500]
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, [], proc.stdout[:500] + proc.stderr[:500]
    ids = [f.get("rule_id", "") for f in data.get("findings", [])]
    return True, ids, ""


def run_external(cmd_prefix: list[str], fixture_dir: Path) -> tuple[bool, list[str], str]:
    try:
        proc = subprocess.run(
            [*cmd_prefix, "scan", str(fixture_dir), "--no-llm", "--format", "json"],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, [], str(exc)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, [], proc.stdout[:500] + proc.stderr[:500]
    if data.get("execution_successful") is False:
        return False, [], "execution_successful=false"
    ids = [issue.get("id", "") for issue in data.get("issues", [])]
    return True, ids, ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skil-binary", default="skil")
    ap.add_argument("--external-cmd", default=None,
                     help="Shell-quoted command prefix for the external scanner, "
                          "e.g. 'uv run --project ../../reference/<clone> <entry-point>'. "
                          "If omitted, only skil is exercised and the report shows skil-only results.")
    ap.add_argument("--filter", default="", help="Comma-separated property id substrings")
    args = ap.parse_args()

    external_cmd = shlex.split(args.external_cmd) if args.external_cmd else None
    properties = load_properties()
    if args.filter:
        wanted = [w.strip() for w in args.filter.split(",") if w.strip()]
        properties = [p for p in properties if any(w in p["id"] for w in wanted)]

    rows = []
    for prop in properties:
        fixture_root = ROOT / "fixtures" / prop["fixture"]
        for polarity in ("positive", "negative"):
            fixture_dir = fixture_root / polarity
            if not fixture_dir.exists():
                continue
            skil_ok, skil_ids, skil_err = run_skil(args.skil_binary, fixture_dir)
            skil_detected = any(rid in skil_ids for rid in prop["skil_rules"])

            row = {
                "property": prop["id"], "polarity": polarity,
                "skil_ok": skil_ok, "skil_detected": skil_detected,
                "skil_ids": skil_ids, "skil_err": skil_err,
            }
            if external_cmd:
                ext_ok, ext_ids, ext_err = run_external(external_cmd, fixture_dir)
                ext_detected = prop["external_rule"] in ext_ids
                row.update({
                    "external_ok": ext_ok, "external_detected": ext_detected,
                    "external_ids": ext_ids, "external_err": ext_err,
                })
            rows.append(row)

    # Report
    header = f"{'property':32} {'polarity':9} {'skil':6}"
    if external_cmd:
        header += f" {'external':9} {'note'}"
    print(header)
    skil_only, external_only, both_miss = [], [], []
    for row in rows:
        skil_mark = "PASS" if row["skil_ok"] and (row["skil_detected"] == (row["polarity"] == "positive")) else "FAIL"
        line = f"{row['property']:32} {row['polarity']:9} {skil_mark:6}"
        if external_cmd:
            ext_mark = "PASS" if row.get("external_ok") and (row.get("external_detected") == (row["polarity"] == "positive")) else "FAIL"
            line += f" {ext_mark:9}"
            if row["polarity"] == "positive":
                if row["skil_detected"] and not row.get("external_detected"):
                    line += " (skil-only detection)"
                elif row.get("external_detected") and not row["skil_detected"]:
                    line += " (external-only detection)"
                    external_only.append(row["property"])
                elif not row["skil_detected"] and not row.get("external_detected"):
                    both_miss.append(row["property"])
        print(line)

    print()
    print("Summary")
    print("-------")
    total = len(rows)
    skil_pass = sum(1 for r in rows if r["skil_ok"] and (r["skil_detected"] == (r["polarity"] == "positive")))
    print(f"skil:     {skil_pass}/{total} PASS")
    if external_cmd:
        ext_pass = sum(1 for r in rows if r.get("external_ok") and (r.get("external_detected") == (r["polarity"] == "positive")))
        print(f"external: {ext_pass}/{total} PASS")
        print(f"Properties external detects that skil does not: {len(external_only)} {external_only}")
        print(f"Properties neither detects: {len(both_miss)} {both_miss}")
    return 0 if skil_pass == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
