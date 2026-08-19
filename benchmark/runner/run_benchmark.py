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


def summarize(fixtures: list[dict], per_fixture: dict, predicate) -> dict:
    scoped = [f for f in fixtures if predicate(f)]
    results = [(f["ground_truth"]["malicious"], per_fixture[f["id"]].get("detected")) for f in scoped]
    confusion = confusion_for(results)
    summary = confusion.as_dict()
    summary["fixture_count"] = len(scoped)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skil-binary", help="path to the skil binary")
    parser.add_argument("--skillspector-binary", help="path to the skillspector binary")
    parser.add_argument("--output", default=str(ROOT / "results" / "latest.json"))
    args = parser.parse_args()

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
    if not tools:
        print("no tool binaries configured; nothing to run", file=sys.stderr)
        return 1

    report = {
        "schema_version": 2,
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
        report["tools"][tool_name] = {
            "identity": run["identity"],
            "headline_metric": headline
            if headline["fixture_count"] > 0
            else "n/a — zero gold-reviewed evaluation fixtures yet, see benchmark/README.md",
            "development_set_metric_regression_only_never_a_generalization_claim": development_informational,
            "evaluation_set_provisional_metric_informational_only": evaluation_provisional_informational,
            "per_fixture": run["per_fixture"],
        }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"wrote {output_path}")

    for tool_name, tool_report in report["tools"].items():
        print(f"\n{tool_name} ({tool_report['identity']}):")
        print(f"  HEADLINE (evaluation, gold only): {tool_report['headline_metric']}")
        print(f"  development set (regression-only, not a claim): {tool_report['development_set_metric_regression_only_never_a_generalization_claim']}")
        print(f"  evaluation set, provisional (informational): {tool_report['evaluation_set_provisional_metric_informational_only']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
