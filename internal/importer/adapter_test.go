package importer

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestNormalizeExternalReportPreservesSubjectAndUnknownSeverity(t *testing.T) {
	art := skil.Artifact{Name: "skill", Digest: "sha256:112233"}
	raw := []byte(`{
		"producer": "extscan",
		"producer_version": "1.2.0",
		"subject_digest": "sha256:112233",
		"findings": [
			{
				"id": "ext-1",
				"rule_id": "R001",
				"title": "Suspicious call",
				"severity": "SEVERE_CUSTOM",
				"file": "run.py",
				"line": 10,
				"message": "custom severity label"
			}
		]
	}`)
	norm, err := NormalizeExternalReport(raw, art)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm.VerificationState != skil.EvidenceObserved {
		t.Fatalf("external adapter findings must be EvidenceObserved, got %s", norm.VerificationState)
	}
	if norm.MaximumSeverity != skil.SeverityUnknown {
		t.Fatalf("unrecognized external severity must map to UNKNOWN, got %s", norm.MaximumSeverity)
	}
	if skil.SeverityRank(norm.MaximumSeverity) < skil.SeverityRank(skil.SeverityHigh) {
		t.Fatalf("UNKNOWN severity must rank at least HIGH, got rank %d", skil.SeverityRank(norm.MaximumSeverity))
	}

	// Mismatched subject digest must fail closed
	otherArt := skil.Artifact{Name: "skill", Digest: "sha256:999999"}
	if _, err := NormalizeExternalReport(raw, otherArt); err == nil {
		t.Fatal("expected subject digest mismatch error")
	}
}
