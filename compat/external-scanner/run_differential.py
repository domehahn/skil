#!/usr/bin/env python3
"""Differential comparison of skil against an external reference scanner.

For every property in properties.yaml, runs both scanners against the
positive and negative fixture, normalizes findings to the shared property
ID, and reports the critical metric: how many properties does the external
scanner detect that skil does not.

Usage:
    python3 run_differential.py \\
        --skil-binary /path/to/skil \\
        [--external-cmd "uv run --project /path/to/reference/clone <entry-point>"]
        [--output /path/to/report.json]
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
    """Returns (ran_ok, observed_rule_ids, raw_stderr_on_failure)."""
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
    ap = argparse.ArgumentParser(description="Differential security-property comparison")
    ap.add_argument("--skil-binary", default="skil")
    ap.add_argument("--external-cmd", default=None,
                     help="Shell-quoted command prefix for the external scanner, "
                          "e.g. 'uv run --project ../../reference/<clone> <entry-point>'. "
                          "If omitted, only skil is exercised.")
    ap.add_argument("--filter", default="",
                     help="Comma-separated property id substrings")
    ap.add_argument("--output", default=None,
                     help="Path to write JSON report")
    args = ap.parse_args()

    external_cmd = shlex.split(args.external_cmd) if args.external_cmd else None
    properties = load_properties()
    if args.filter:
        wanted = [w.strip() for w in args.filter.split(",") if w.strip()]
        properties = [p for p in properties if any(w in p["id"] for w in wanted)]

    results = []
    for prop in properties:
        fixture_root = ROOT / "fixtures" / prop["fixture"]
        entry = {
            "property": prop["id"],
            "fixture": prop["fixture"],
            "skil_rules": prop["skil_rules"],
            "external_rule": prop["external_rule"],
            "positive": {"skil": {}, "external": {}},
            "negative": {"skil": {}, "external": {}},
        }
        for polarity in ("positive", "negative"):
            fixture_dir = fixture_root / polarity
            if not fixture_dir.exists():
                continue

            # skil
            skil_ok, skil_ids, skil_err = run_skil(args.skil_binary, fixture_dir)
            skil_detected = any(rid in skil_ids for rid in prop["skil_rules"])
            entry[polarity]["skil"] = {
                "ok": skil_ok,
                "detected": skil_detected,
                "rule_ids": skil_ids,
                "error": skil_err,
            }

            # external
            if external_cmd:
                ext_ok, ext_ids, ext_err = run_external(external_cmd, fixture_dir)
                ext_detected = prop["external_rule"] in ext_ids
                entry[polarity]["external"] = {
                    "ok": ext_ok,
                    "detected": ext_detected,
                    "rule_ids": ext_ids,
                    "error": ext_err,
                }
        results.append(entry)

    # Derive normalized property-level assessment
    skil_only_props = []
    external_only_props = []
    both_detect_props = []
    neither_detect_props = []

    for entry in results:
        pos_skil = entry["positive"]["skil"].get("detected", False)
        pos_ext = entry["positive"].get("external", {}).get("detected", False) if external_cmd else None

        # Normalize: property detected iff positive fixture triggered, negative did not
        skil_pass = pos_skil and not entry["negative"]["skil"].get("detected", False)
        ext_pass = None
        if external_cmd:
            ext_pass = pos_ext and not entry["negative"].get("external", {}).get("detected", False) if entry["negative"].get("external", {}).get("ok") else pos_ext

        entry["skil_pass"] = skil_pass
        entry["external_pass"] = ext_pass

        if external_cmd:
            if skil_pass and not ext_pass:
                skil_only_props.append(entry["property"])
            elif ext_pass and not skil_pass:
                external_only_props.append(entry["property"])
            elif skil_pass and ext_pass:
                both_detect_props.append(entry["property"])
            else:
                neither_detect_props.append(entry["property"])

    # Terminal report
    header = f"{'property':32} {'positive( skil | ext )':22} {'negative( skil | ext )':22}"
    if not external_cmd:
        header = f"{'property':32} {'positive skil':14} {'negative skil':14}"
    print(header)
    print("-" * len(header))

    for entry in results:
        pos_s = "PASS" if entry["positive"]["skil"]["detected"] else "—"
        neg_s = "PASS" if not entry["negative"]["skil"].get("detected", False) else "FAIL"
        if external_cmd:
            pos_e = "PASS" if entry["positive"].get("external", {}).get("detected") else "—"
            neg_e = "PASS" if not entry["negative"].get("external", {}).get("detected", False) else "FAIL"
            line = f"{entry['property']:32} {f'{pos_s:>4} | {pos_e:<4}':22} {f'{neg_s:>4} | {neg_e:<4}':22}"
        else:
            line = f"{entry['property']:32} {pos_s:>6}      {neg_s:>6}"
        print(line)

    print()
    total = len(results)
    skil_pass_count = sum(1 for e in results if e["skil_pass"])
    print(f"skil property detection: {skil_pass_count}/{total}")

    if external_cmd:
        ext_pass_count = sum(1 for e in results if e.get("external_pass"))
        print(f"external property detection: {ext_pass_count}/{total}")
        print()
        print(f"Properties both detect:    {len(both_detect_props)} {both_detect_props}")
        print(f"Properties skil-only:      {len(skil_only_props)} {skil_only_props}")
        print(f"Properties external-only:  {len(external_only_props)} {external_only_props}")
        print(f"Properties neither:        {len(neither_detect_props)} {neither_detect_props}")
        print()

    # The critical metric: external-only should be 0
    if external_only_props:
        print(f"*** GAP: {len(external_only_props)} properties detected by external scanner but NOT by skil: {external_only_props}")
    else:
        print("No gaps: zero properties where the external scanner detects something skil does not.")

    # JSON output
    if args.output:
        report = {
            "schema_version": "1.0.0",
            "commit": {"skil": None, "external": None},
            "results": results,
            "summary": {
                "total": total,
                "skil_pass": skil_pass_count,
                "external_pass": ext_pass_count if external_cmd else None,
                "skil_only": skil_only_props,
                "external_only": external_only_props,
                "both_detect": both_detect_props,
                "neither": neither_detect_props,
                "gap": bool(external_only_props),
            },
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nReport written to {args.output}")

    return 1 if external_only_props else 0


if __name__ == "__main__":
    raise SystemExit(main())
