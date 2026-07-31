#!/usr/bin/env python3
"""Differential comparison of skil against an external reference scanner.

For every (property, fixture) in properties.yaml, runs both scanners against
the positive and negative fixture, normalizes findings to the shared property
ID, and reports the critical metric: how many properties does the external
scanner detect that skil does not.

Three suites are supported:
- static (default): skil offline scan vs external scanner with --no-llm
- semantic:        skil --semantic vs external scanner with LLM enabled
- provider:        skil scans that require a runtime provider (OSV query,
                   YARA binary) and are excluded from the offline CI gate

Per-fixture `scan_args` (e.g. `--osv`, `--yara-builtin`) are appended to the
skil command line only for that fixture.

External rule normalization: fixtures declare `external_rules` as the list
of rule IDs the reference scanner actually emits (it may collapse several skil
sub-variants into one rule ID, e.g. P2 for HTML/Markdown/zero-width hidden
instructions). A fixture is detected on the external side if ANY declared
external rule ID appears in the scanner output.

Usage:
    python3 run_differential.py \\
        --skil-binary /path/to/skil \\
        [--external-cmd "uv run --project /path/to/reference/clone <entry-point>"]
        [--suite static|semantic|provider|all]
        [--semantic-skil-args ...] [--semantic-ext-args ...]
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
REPO = ROOT.parent.parent


def load_properties() -> list[dict]:
    with open(ROOT / "properties.yaml") as f:
        return yaml.safe_load(f)["properties"]


def run_skil(binary: str, fixture_dir: Path, extra_args: list[str]) -> tuple[bool, list[str], str]:
    """Returns (ran_ok, observed_rule_ids, raw_stderr_on_failure)."""
    cmd = [binary, "scan", str(fixture_dir), "--format", "json", *extra_args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
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


def run_external(cmd_prefix: list[str], fixture_dir: Path, extra_args: list[str]) -> tuple[bool, list[str], str]:
    """Returns (ran_ok, observed_rule_ids, raw_stderr_on_failure)."""
    try:
        proc = subprocess.run(
            [*cmd_prefix, "scan", str(fixture_dir), *extra_args, "--format", "json"],
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


def external_detected(fixture: dict, ext_ids: list[str]) -> bool:
    rules = fixture.get("external_rules") or [fixture.get("external_rule", "")]
    return any(rid in ext_ids for rid in rules)


def git_head(path: Path) -> str | None:
    try:
        proc = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def skil_version_metadata(skil_binary: str) -> dict:
    """Reads commit + prompt_version from `skil version --format json`."""
    try:
        proc = subprocess.run([skil_binary, "version", "--format", "json"],
                              capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            return {}
        return json.loads(proc.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {}


def parse_model_from_args(*arg_lists: str) -> str | None:
    for arg_list in arg_lists:
        parts = shlex.split(arg_list)
        for i, part in enumerate(parts):
            if part in ("--semantic-model", "--model") and i + 1 < len(parts):
                return parts[i + 1]
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Differential security-property comparison")
    ap.add_argument("--skil-binary", default="skil")
    ap.add_argument("--external-cmd", default=None,
                     help="Shell-quoted command prefix for the external scanner, "
                          "e.g. 'uv run --project ../../reference/<clone> <entry-point>'. "
                          "If omitted, only skil is exercised.")
    ap.add_argument("--filter", default="",
                     help="Comma-separated property id substrings")
    ap.add_argument("--suite", choices=["static", "semantic", "provider", "all"], default="all",
                     help="Which suite to exercise. Semantic requires a configured LLM "
                          "provider on both sides and is excluded from the CI gate; "
                          "provider exercises scans that need a runtime provider.")
    ap.add_argument("--semantic-skil-args", default="--semantic",
                     help="Extra args passed to skil scan in the semantic suite")
    ap.add_argument("--semantic-ext-args", default="",
                     help="Extra args passed to the external scanner in the semantic suite "
                          "(omit --no-llm and pass provider/model flags)")
    ap.add_argument("--skip-different-by-design", action="store_true",
                     help="Skip DIFFERENT_BY_DESIGN fixtures (they intentionally do not "
                          "produce scanner findings and are not part of the replacement gate)")
    ap.add_argument("--external-repo", default=None,
                     help="Path to the external scanner checkout; its HEAD revision is "
                          "recorded in the report as the external scanner digest")
    ap.add_argument("--model", default=None,
                     help="LLM model identifier used for the semantic suite; recorded in "
                          "the report for reproducibility. If omitted, it is parsed from "
                          "--semantic-skil-args/--semantic-ext-args (--semantic-model X).")
    ap.add_argument("--prompt-version", default=None,
                     help="Semantic prompt version to record. If omitted, it is read from "
                          "`skil version --format json` when the skil binary supports it.")
    ap.add_argument("--output", default=None,
                     help="Path to write JSON report")
    args = ap.parse_args()

    external_cmd = shlex.split(args.external_cmd) if args.external_cmd else None
    properties = load_properties()
    if args.filter:
        wanted = [w.strip() for w in args.filter.split(",") if w.strip()]
        properties = [p for p in properties if any(w in p["id"] for w in wanted)]
    if args.suite != "all":
        properties = [p for p in properties if any(f.get("suite") == args.suite for f in p["fixtures"])]
    if args.skip_different_by_design:
        properties = [p for p in properties if any(f.get("status") != "DIFFERENT_BY_DESIGN" for f in p["fixtures"])]

    fixtures = [
        (prop, fixture)
        for prop in properties
        for fixture in prop["fixtures"]
    ]

    results = []
    for prop, fixture in fixtures:
        fixture_root = ROOT / "fixtures" / fixture["fixture"]
        skii_extra = (shlex.split(args.semantic_skil_args) if args.semantic_skil_args else []) if fixture.get("suite") == "semantic" else []
        if fixture.get("scan_args"):
            skii_extra += shlex.split(fixture["scan_args"])
        ext_extra = shlex.split(args.semantic_ext_args) if fixture.get("suite") == "semantic" else ["--no-llm"]
        entry = {
            "property": prop["id"],
            "fixture": fixture["fixture"],
            "suite": fixture.get("suite", "static"),
            "skil_rules": fixture["skil_rules"],
            "external_rules": fixture.get("external_rules", [fixture.get("external_rule", "")]),
            "positive": {"skil": {}, "external": {}},
            "negative": {"skil": {}, "external": {}},
        }
        for polarity in ("positive", "negative"):
            fixture_dir = fixture_root / polarity
            if not fixture_dir.exists():
                continue

            # skil
            skil_ok, skil_ids, skil_err = run_skil(args.skil_binary, fixture_dir, skii_extra)
            skil_detected = any(rid in skil_ids for rid in fixture["skil_rules"])
            entry[polarity]["skil"] = {
                "ok": skil_ok,
                "detected": skil_detected,
                "rule_ids": skil_ids,
                "error": skil_err,
            }

            # external
            if external_cmd:
                ext_ok, ext_ids, ext_err = run_external(external_cmd, fixture_dir, ext_extra)
                ext_detected = external_detected(fixture, ext_ids)
                entry[polarity]["external"] = {
                    "ok": ext_ok,
                    "detected": ext_detected,
                    "rule_ids": ext_ids,
                    "error": ext_err,
                }
        results.append(entry)

    # Derive normalized fixture-level assessment
    skil_only_props = []
    external_only_props = []
    both_detect_props = []
    neither_detect_props = []

    for entry in results:
        pos_skil = entry["positive"]["skil"].get("detected", False)
        pos_ext = entry["positive"].get("external", {}).get("detected", False) if external_cmd else None

        # Normalize: fixture detected iff positive fixture triggered, negative did not
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
    print(f"skil fixture detection: {skil_pass_count}/{total}")

    if external_cmd:
        ext_pass_count = sum(1 for e in results if e.get("external_pass"))
        print(f"external fixture detection: {ext_pass_count}/{total}")
        print()
        print(f"Fixtures both detect:    {len(both_detect_props)} {both_detect_props}")
        print(f"Fixtures skil-only:      {len(skil_only_props)} {skil_only_props}")
        print(f"Fixtures external-only:  {len(external_only_props)} {external_only_props}")
        print(f"Fixtures neither:        {len(neither_detect_props)} {neither_detect_props}")
        print()

    # The critical metric: external-only should be 0
    if external_only_props:
        print(f"*** GAP: {len(external_only_props)} fixtures detected by external scanner but NOT by skil: {external_only_props}")
    else:
        print("No gaps: zero fixtures where the external scanner detects something skil does not.")

    # JSON output
    if args.output:
        skil_meta = skil_version_metadata(args.skil_binary)
        model = args.model or parse_model_from_args(args.semantic_skil_args, args.semantic_ext_args)
        external_repo = Path(args.external_repo).expanduser() if args.external_repo else None
        report = {
            "schema_version": "2.1.0",
            "commit": {
                "skil": skil_meta.get("commit") or git_head(REPO),
                "external": git_head(external_repo) if external_repo else None,
            },
            "scanner_version": {
                "skil": skil_meta.get("version"),
                "external": None,
            },
            "suite": args.suite,
            "model": model,
            "prompt_version": args.prompt_version or skil_meta.get("prompt_version"),
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
