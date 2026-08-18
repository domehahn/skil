#!/usr/bin/env python3
"""Vendor-neutral benchmark runner.

Loads every fixture under benchmark/corpus/, runs each configured tool
adapter against its artifact, and reports TP/FP/TN/FN/Precision/Recall/F1/FPR
per tool.

Only fixtures with review.status == "gold" (at least two independent human
reviewers) count toward the headline metric — see benchmark/README.md for
why. Provisional fixtures are still run and reported, clearly labeled as
informational only. As of this runner's initial version, the corpus has zero
gold fixtures, so the headline metric is expected to read "n/a" until real
review happens; that is the runner working correctly, not a bug.

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
sys.path.insert(0, str(ADAPTERS_DIR))

from metrics import confusion_for  # noqa: E402


def load_adapter(name: str):
    spec = importlib.util.spec_from_file_location(name, ADAPTERS_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_fixtures() -> list[dict]:
    fixtures = []
    for fixture_dir in sorted(CORPUS.iterdir()):
        manifest_path = fixture_dir / "fixture.yaml"
        if not manifest_path.is_file():
            continue
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)
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


def summarize(fixtures: list[dict], per_fixture: dict, statuses: set[str]) -> dict:
    scoped = [f for f in fixtures if f["review"]["status"] in statuses]
    results = []
    for fixture in scoped:
        outcome = per_fixture[fixture["id"]]
        results.append((fixture["ground_truth"]["malicious"], outcome.get("detected")))
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

    fixtures = load_fixtures()
    if not fixtures:
        print("no fixtures found under benchmark/corpus/", file=sys.stderr)
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
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus": {
            "fixture_count": len(fixtures),
            "gold_fixture_count": sum(1 for f in fixtures if f["review"]["status"] == "gold"),
            "digest": corpus_digest(fixtures),
        },
        "tools": {},
    }

    for tool_name, run in tools.items():
        gold = summarize(fixtures, run["per_fixture"], {"gold"})
        provisional_informational = summarize(fixtures, run["per_fixture"], {"gold", "provisional"})
        report["tools"][tool_name] = {
            "identity": run["identity"],
            "headline_metric": gold if gold["fixture_count"] > 0 else "n/a — zero gold-reviewed fixtures yet, see benchmark/README.md",
            "informational_metric_including_provisional_fixtures": provisional_informational,
            "per_fixture": run["per_fixture"],
        }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"wrote {output_path}")

    for tool_name, tool_report in report["tools"].items():
        print(f"\n{tool_name} ({tool_report['identity']}):")
        print(f"  headline (gold only): {tool_report['headline_metric']}")
        print(f"  informational (gold+provisional): {tool_report['informational_metric_including_provisional_fixtures']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
