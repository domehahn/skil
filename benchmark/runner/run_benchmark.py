#!/usr/bin/env python3
"""Vendor-neutral benchmark runner.

Loads every fixture under benchmark/corpus/{development,evaluation}/, runs
each configured tool adapter against its artifact, and reports
TP/FP/TN/FN/Precision/Recall/F1/FPR per tool.

Two independent gates must both pass before a number counts as the
headline metric:

1. tier == "evaluation" — the fixture lives in the blind holdout, not the
   public development set. A fixture that has ever been used to diagnose
   or fix a scanner bug belongs in development/ permanently and must never
   move to evaluation/ — see benchmark/README.md's "Development vs.
   evaluation" section for why, and this file's `validate_tier_matches_dir`
   for the mechanical check that catches a fixture claiming the wrong
   tier for the directory it's actually in.
2. review.status == "gold" — at least two independent human reviewers
   have confirmed the fixture's ground truth.

As of this runner's initial version, evaluation/ is empty (all 12 starter
fixtures are development-tier, provisional), so the headline metric
correctly reads "n/a" for every tool. That is the runner working as
designed, not a bug.

The development-tier metric is still computed and reported, clearly
labeled as informational/regression-only: it answers "did we regress on
known cases," never "how well does this generalize."

Usage:
    python3 run_benchmark.py \
        --skil-binary /path/to/skil \
        --skillspector-binary skillspector \
        --output results/latest.json

Pinned vs. rolling mode, and measurement evidence
--------------------------------------------------
--mode pinned (the default) verifies each reference scanner's reported
--version output against the exact version/commit recorded in
pinned-versions.json, so a result can be reproduced later against a known,
fixed competitor release rather than silently drifting whenever upstream
cuts a new one. A mismatch is recorded (per tool, `pinned_version_verified:
false`) rather than silently ignored or treated as fatal -- the metric is
still computed and reported, just honestly labeled as not reproducible
against the pin. --mode rolling skips that check entirely, intentionally
measuring against whatever is actually installed (catching upstream drift
is the point of that mode); this is what the weekly CI cron runs alongside
the pinned mode, so both a stable baseline and a live drift signal exist
side by side.

Every run embeds a top-level "evidence" block: a SHA-256 digest
(`measurement_digest_sha256`) over a canonical JSON encoding of every input
that determines the reported numbers -- the corpus digest, each tool's
identity and pin-verification outcome, and every reported metric. Changing
any one of those (a single fixture byte, a tool version, one metric) changes
the digest. This is a self-verifying tamper-evidence chain, not an
asymmetric signature: signing would need a private key, and this benchmark
deliberately carries no secrets (see benchmark/README.md); anyone with the
published results.json can recompute the same digest with
verify_evidence.py and confirm it matches, without trusting anything but
SHA-256 and the canonicalization documented in evidence_payload() below.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
ADAPTERS_DIR = ROOT / "adapters"
TIERS = ("development", "evaluation")
sys.path.insert(0, str(ADAPTERS_DIR))

from metrics import confusion_for  # noqa: E402


def load_adapter(name: str):
    spec = importlib.util.spec_from_file_location(name, ADAPTERS_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_tier_matches_dir(manifest: dict, tier_dir_name: str) -> None:
    declared = manifest.get("tier")
    if declared != tier_dir_name:
        raise ValueError(
            f"{manifest.get('id', '<unknown>')}: fixture.yaml declares tier "
            f"'{declared}' but lives under corpus/{tier_dir_name}/ — these must match"
        )


def load_fixtures() -> list[dict]:
    fixtures = []
    for tier in TIERS:
        tier_dir = CORPUS / tier
        if not tier_dir.is_dir():
            continue
        for fixture_dir in sorted(tier_dir.iterdir()):
            manifest_path = fixture_dir / "fixture.yaml"
            if not manifest_path.is_file():
                continue
            with open(manifest_path) as f:
                manifest = yaml.safe_load(f)
            validate_tier_matches_dir(manifest, tier)
            manifest["_dir"] = fixture_dir
            manifest["_artifact"] = fixture_dir / manifest["artifact"]["root"]
            fixtures.append(manifest)
    return fixtures


def corpus_digest(fixtures: list[dict]) -> str:
    digest = hashlib.sha256()
    for fixture in fixtures:
        for path in sorted(fixture["_dir"].rglob("*")):
            if path.is_file():
                digest.update(str(path.relative_to(ROOT)).encode())
                digest.update(path.read_bytes())
    return digest.hexdigest()


def run_tool(adapter_name: str, binary: str, fixtures: list[dict]) -> dict:
    adapter = load_adapter(adapter_name)
    identity = adapter.identity(binary)
    per_fixture = {}
    for fixture in fixtures:
        outcome = adapter.scan(binary, fixture["_artifact"])
        per_fixture[fixture["id"]] = outcome
    return {"identity": identity, "per_fixture": per_fixture}


def load_pinned_versions(path: Path) -> dict:
    if not path.is_file():
        return {}
    with open(path) as f:
        return json.load(f)


def verify_pin(tool_name: str, identity: dict, pinned: dict) -> tuple[str | None, bool | None]:
    """Returns (expected_version_or_commit, verified) for a tool with a
    pinned-versions.json entry, or (None, None) when the tool has no pin
    (skil itself, or a reference tool this corpus hasn't pinned yet).
    Verification is a case-insensitive substring check of the pinned
    version/commit tag inside the adapter's own --version output -- robust
    to each tool's own free-form version-string formatting, without
    depending on an exact byte-for-byte match this benchmark doesn't
    control."""
    entry = pinned.get(tool_name)
    if not entry:
        return None, None
    expected = entry.get("tag") or entry.get("version")
    if not expected:
        return None, None
    reported = str(identity.get("version", ""))
    needle = expected.lstrip("v").lower()
    return expected, needle in reported.lower()


def summarize(fixtures: list[dict], per_fixture: dict, predicate) -> dict:
    scoped = [f for f in fixtures if predicate(f)]
    results = [(f["ground_truth"]["malicious"], per_fixture[f["id"]].get("detected")) for f in scoped]
    confusion = confusion_for(results)
    summary = confusion.as_dict()
    summary["fixture_count"] = len(scoped)
    return summary


def canonical_json(value) -> bytes:
    """A deterministic, minimal-whitespace, sorted-key JSON encoding: the
    same evidence dict always serializes to the exact same bytes, so its
    SHA-256 digest is reproducible by anyone re-running this function
    against the same published JSON values -- no dependency on this
    process's own dict insertion order or key ordering."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def evidence_payload(report: dict) -> dict:
    """The exact subset of the report that measurement_digest_sha256 binds:
    every input that determines the reported numbers, and nothing that
    could change from one otherwise-identical run to the next (results
    file paths, wall-clock duration, etc. are deliberately excluded)."""
    tools = {}
    for name, tool_report in sorted(report["tools"].items()):
        tools[name] = {
            "identity": tool_report["identity"],
            "pinned_expected_version": tool_report.get("pinned_expected_version"),
            "pinned_version_verified": tool_report.get("pinned_version_verified"),
            "headline_metric": tool_report["headline_metric"],
            "development_set_metric_regression_only_never_a_generalization_claim": tool_report[
                "development_set_metric_regression_only_never_a_generalization_claim"
            ],
            "evaluation_set_provisional_metric_informational_only": tool_report[
                "evaluation_set_provisional_metric_informational_only"
            ],
        }
    return {
        "schema_version": report["schema_version"],
        "benchmark_mode": report["benchmark_mode"],
        "generated_at": report["generated_at"],
        "corpus_digest": report["corpus"]["digest"],
        "tools": tools,
    }


def measurement_digest(report: dict) -> str:
    return hashlib.sha256(canonical_json(evidence_payload(report))).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skil-binary", help="path to the skil binary")
    parser.add_argument("--skillspector-binary", help="path to the skillspector binary")
    parser.add_argument("--cisco-skill-scanner-binary", help="path to the skill-scanner binary")
    parser.add_argument("--mode", choices=["pinned", "rolling"], default="pinned", help="benchmark mode: pinned baseline vs rolling current")
    parser.add_argument("--pinned-versions", default=str(ROOT / "pinned-versions.json"), help="exact reference-scanner versions 'pinned' mode verifies against")
    parser.add_argument("--output", default=str(ROOT / "results" / "latest.json"))
    args = parser.parse_args()

    pinned_versions = load_pinned_versions(Path(args.pinned_versions)) if args.mode == "pinned" else {}

    try:
        fixtures = load_fixtures()
    except ValueError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        return 1
    if not fixtures:
        print("no fixtures found under benchmark/corpus/{development,evaluation}/", file=sys.stderr)
        return 1

    tools = {}
    if args.skil_binary:
        tools["skil"] = run_tool("skil_adapter", args.skil_binary, fixtures)
    if args.skillspector_binary:
        tools["skillspector"] = run_tool("skillspector_adapter", args.skillspector_binary, fixtures)
    if args.cisco_skill_scanner_binary:
        tools["cisco-skill-scanner"] = run_tool("cisco_skill_scanner_adapter", args.cisco_skill_scanner_binary, fixtures)
    if not tools:
        print("no tool binaries configured; nothing to run", file=sys.stderr)
        return 1

    report = {
        "schema_version": 2,
        "benchmark_mode": args.mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus": {
            "fixture_count": len(fixtures),
            "development_fixture_count": sum(1 for f in fixtures if f["tier"] == "development"),
            "evaluation_fixture_count": sum(1 for f in fixtures if f["tier"] == "evaluation"),
            "evaluation_gold_fixture_count": sum(
                1 for f in fixtures if f["tier"] == "evaluation" and f["review"]["status"] == "gold"
            ),
            "digest": corpus_digest(fixtures),
        },
        "tools": {},
    }

    for tool_name, run in tools.items():
        headline = summarize(
            fixtures, run["per_fixture"], lambda f: f["tier"] == "evaluation" and f["review"]["status"] == "gold"
        )
        development_informational = summarize(fixtures, run["per_fixture"], lambda f: f["tier"] == "development")
        evaluation_provisional_informational = summarize(
            fixtures, run["per_fixture"], lambda f: f["tier"] == "evaluation" and f["review"]["status"] == "provisional"
        )
        expected_pin, pin_verified = verify_pin(tool_name, run["identity"], pinned_versions)
        report["tools"][tool_name] = {
            "identity": run["identity"],
            "pinned_expected_version": expected_pin,
            "pinned_version_verified": pin_verified,
            "headline_metric": headline
            if headline["fixture_count"] > 0
            else "n/a — zero gold-reviewed evaluation fixtures yet, see benchmark/README.md",
            "development_set_metric_regression_only_never_a_generalization_claim": development_informational,
            "evaluation_set_provisional_metric_informational_only": evaluation_provisional_informational,
            "per_fixture": run["per_fixture"],
        }

    report["evidence"] = {
        "algorithm": "sha256",
        "canonicalization": "python json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=True), utf-8 encoded",
        "measurement_digest_sha256": measurement_digest(report),
        "verify_with": "benchmark/runner/verify_evidence.py",
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"wrote {output_path}")

    for tool_name, tool_report in report["tools"].items():
        print(f"\n{tool_name} ({tool_report['identity']}):")
        if tool_report["pinned_expected_version"] is not None:
            status = "verified" if tool_report["pinned_version_verified"] else "MISMATCH — not reproducible against the pin"
            print(f"  pinned version {tool_report['pinned_expected_version']}: {status}")
        print(f"  HEADLINE (evaluation, gold only): {tool_report['headline_metric']}")
        print(f"  development set (regression-only, not a claim): {tool_report['development_set_metric_regression_only_never_a_generalization_claim']}")
        print(f"  evaluation set, provisional (informational): {tool_report['evaluation_set_provisional_metric_informational_only']}")

    print(f"\nmeasurement_digest_sha256: {report['evidence']['measurement_digest_sha256']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
