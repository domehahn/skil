#!/usr/bin/env python3
"""Recomputes and checks a benchmark results.json's measurement_digest_sha256.

Anyone who has a published results.json can run this without trusting
anything but SHA-256: it re-derives the exact same evidence payload
run_benchmark.py bound the digest to (see that file's evidence_payload()
and measurement_digest()) purely from the published JSON's own fields, and
confirms the recomputed digest matches report["evidence"]
["measurement_digest_sha256"]. A mismatch means either the file was
altered after it was produced, or it was produced by a version of
run_benchmark.py whose evidence_payload() differs from this one -- either
way, the reported numbers are not verifiably the ones that were actually
measured.

This is deliberately a digest check, not a signature check: this
benchmark carries no private key and no secret (see benchmark/README.md),
so there is nothing to verify a signature against. What this script proves
is narrower and still meaningful: the numbers in this file are internally
consistent with each other and with the corpus/tool-identity fields also
in this file -- not that the file came from any particular trusted party.

Usage:
    python3 verify_evidence.py results/latest.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_benchmark import (  # noqa: E402
    EVIDENCE_ALGORITHM,
    EVIDENCE_CANONICALIZATION,
    canonical_json,
    evidence_payload,
)
import hashlib  # noqa: E402


def verify_report(report: dict) -> list[str]:
    """Returns a list of human-readable problem descriptions; empty means
    fully verified. Checked independently of each other, so a caller sees
    every real problem in one pass rather than stopping at the first."""
    problems = []
    evidence = report.get("evidence")
    if not evidence or "measurement_digest_sha256" not in evidence:
        return ["no evidence.measurement_digest_sha256 field found"]

    # The algorithm/canonicalization fields describe what this verifier
    # actually does; they are not themselves part of the digest's own bound
    # payload, so a tampered file could claim a different method here while
    # the digest below still matches (recomputed with *this* verifier's
    # real, fixed method regardless of what the file claims). Checking them
    # against the real constants closes that gap: a claim that doesn't
    # match what was actually used to produce a verifiable digest is
    # reported as its own failure, not silently accepted.
    if evidence.get("algorithm") != EVIDENCE_ALGORITHM:
        problems.append(f"evidence.algorithm claims {evidence.get('algorithm')!r}, this verifier uses {EVIDENCE_ALGORITHM!r}")
    if evidence.get("canonicalization") != EVIDENCE_CANONICALIZATION:
        problems.append(f"evidence.canonicalization claims {evidence.get('canonicalization')!r}, this verifier uses {EVIDENCE_CANONICALIZATION!r}")

    recomputed = hashlib.sha256(canonical_json(evidence_payload(report))).hexdigest()
    claimed = evidence["measurement_digest_sha256"]
    if recomputed != claimed:
        problems.append(f"claimed digest {claimed}, recomputed {recomputed}")

    return problems


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_evidence.py <results.json>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    report = json.loads(path.read_text())

    problems = verify_report(report)
    if problems:
        for problem in problems:
            print(f"MISMATCH: {problem}", file=sys.stderr)
        print("this file's measurements are not verifiably intact", file=sys.stderr)
        return 1

    print(f"OK: measurement_digest_sha256 verified ({report['evidence']['measurement_digest_sha256']})")
    for tool_name, tool_report in report.get("tools", {}).items():
        pin = tool_report.get("pinned_expected_version")
        if pin is not None:
            verified = tool_report.get("pinned_version_verified")
            print(f"  {tool_name}: pinned {pin} -> {'verified' if verified else 'MISMATCH'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
