#!/usr/bin/env python3
"""Regression tests for pin verification and measurement-evidence binding."""

import hashlib
import unittest

from run_benchmark import (
    canonical_json,
    evidence_payload,
    measurement_digest,
    verify_pin,
)


class VerifyPinTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pinned = {
            "skillspector": {"tag": "v2.11.0"},
            "cisco-skill-scanner": {"version": "2.0.14"},
        }

    def test_matching_tag_verifies(self) -> None:
        expected, verified = verify_pin(
            "skillspector", {"version": "SkillSpector v2.11.0"}, self.pinned
        )
        self.assertEqual(expected, "v2.11.0")
        self.assertTrue(verified)

    def test_mismatched_tag_fails_without_raising(self) -> None:
        expected, verified = verify_pin(
            "skillspector", {"version": "SkillSpector v2.9.0"}, self.pinned
        )
        self.assertEqual(expected, "v2.11.0")
        self.assertFalse(verified)

    def test_matching_version_field_verifies(self) -> None:
        expected, verified = verify_pin(
            "cisco-skill-scanner", {"version": "cisco-ai-skill-scanner 2.0.14"}, self.pinned
        )
        self.assertEqual(expected, "2.0.14")
        self.assertTrue(verified)

    def test_unpinned_tool_returns_none_none(self) -> None:
        # skil itself has no pinned-versions.json entry, and any tool
        # missing from a supplied mapping (e.g. --mode rolling's empty
        # mapping) must not be reported as verified or unverified — it was
        # never checked at all.
        expected, verified = verify_pin("skil", {"version": "0.1.0"}, self.pinned)
        self.assertIsNone(expected)
        self.assertIsNone(verified)

    def test_empty_pinned_mapping_is_a_no_op(self) -> None:
        expected, verified = verify_pin("skillspector", {"version": "v2.11.0"}, {})
        self.assertIsNone(expected)
        self.assertIsNone(verified)


class MeasurementDigestTest(unittest.TestCase):
    def make_report(self, **overrides) -> dict:
        report = {
            "schema_version": 2,
            "benchmark_mode": "pinned",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "corpus": {"digest": "abc123"},
            "tools": {
                "skil": {
                    "identity": {"tool": "skil", "version": "0.1.0"},
                    "pinned_expected_version": None,
                    "pinned_version_verified": None,
                    "headline_metric": "n/a",
                    "development_set_metric_regression_only_never_a_generalization_claim": {"tp": 1},
                    "evaluation_set_provisional_metric_informational_only": {"tp": 0},
                }
            },
        }
        report.update(overrides)
        return report

    def test_digest_is_deterministic_across_key_order(self) -> None:
        a = self.make_report()
        b = {  # same content, different construction order
            "tools": a["tools"],
            "corpus": a["corpus"],
            "generated_at": a["generated_at"],
            "benchmark_mode": a["benchmark_mode"],
            "schema_version": a["schema_version"],
        }
        self.assertEqual(measurement_digest(a), measurement_digest(b))

    def test_digest_changes_when_a_metric_changes(self) -> None:
        a = self.make_report()
        b = self.make_report()
        b["tools"]["skil"]["development_set_metric_regression_only_never_a_generalization_claim"] = {"tp": 2}
        self.assertNotEqual(measurement_digest(a), measurement_digest(b))

    def test_digest_changes_when_corpus_digest_changes(self) -> None:
        a = self.make_report()
        b = self.make_report(corpus={"digest": "different"})
        self.assertNotEqual(measurement_digest(a), measurement_digest(b))

    def test_digest_changes_when_pin_verification_outcome_changes(self) -> None:
        a = self.make_report()
        b = self.make_report()
        b["tools"]["skil"]["pinned_version_verified"] = False
        self.assertNotEqual(measurement_digest(a), measurement_digest(b))

    def test_digest_is_a_real_sha256_of_the_documented_payload(self) -> None:
        report = self.make_report()
        expected = hashlib.sha256(canonical_json(evidence_payload(report))).hexdigest()
        self.assertEqual(measurement_digest(report), expected)
        self.assertEqual(len(expected), 64)

    def test_evidence_payload_excludes_per_fixture_detail(self) -> None:
        # per_fixture detail is real content (rule IDs, verdicts per
        # fixture) but isn't part of what the digest binds -- it's fully
        # implied by (and would itself have to be re-derived from) the
        # metrics the digest already covers, and keeping the bound payload
        # small keeps this test's assertions about it meaningful.
        report = self.make_report()
        report["tools"]["skil"]["per_fixture"] = {"bench-001": {"detected": True}}
        payload = evidence_payload(report)
        self.assertNotIn("per_fixture", payload["tools"]["skil"])


if __name__ == "__main__":
    unittest.main()
