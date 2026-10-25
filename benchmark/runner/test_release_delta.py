import unittest

from release_delta import CaseResult, release_delta


class ReleaseDeltaTest(unittest.TestCase):
    def test_reports_new_upstream_gap_on_same_original_corpus(self):
        report = release_delta(
            [CaseResult("original-context-loss", False)],
            [CaseResult("original-context-loss", True)],
            [CaseResult("original-context-loss", False)],
        )
        self.assertTrue(report["complete"])
        self.assertEqual(["original-context-loss"], report["skil_gaps"])

    def test_refuses_mismatched_corpora(self):
        report = release_delta(
            [CaseResult("a", False)], [CaseResult("b", True)], [CaseResult("a", True)]
        )
        self.assertFalse(report["complete"])


if __name__ == "__main__":
    unittest.main()
