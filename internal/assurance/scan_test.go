package assurance

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestAssessScanDoesNotInferSuccessFromNoFindings(t *testing.T) {
	scan := skil.ScanResult{Artifact: skil.Artifact{Digest: "sha256:a"}, Findings: nil,
		Inspection: []skil.InspectionWorkItem{{Analyzer: "semantic", Version: "1", File: "SKILL.md", Outcome: skil.InspectionFailed, Reason: "provider invocation failed"}}}
	report := AssessScan(scan)
	if report.Outcome != skil.OutcomePartial {
		t.Fatalf("got %s", report.Outcome)
	}
	if len(report.Limitations) < 1 || report.Limitations[0].Analyzer != "semantic" {
		t.Fatalf("missing analyzer attribution: %#v", report.Limitations)
	}
	if err := report.Proof.Validate(); err != nil {
		t.Fatalf("invalid outcome proof: %v", err)
	}
}

func TestAssessScanMarksSuccessfulZeroFindingWorkComplete(t *testing.T) {
	scan := skil.ScanResult{Artifact: skil.Artifact{Digest: "sha256:a"}, ProofPersisted: true,
		Inspection: []skil.InspectionWorkItem{{Analyzer: "pattern", Version: "1", File: "SKILL.md", Outcome: skil.InspectionCompleted}}}
	report := AssessScan(scan)
	if report.Outcome != skil.OutcomeComplete {
		t.Fatalf("got %s", report.Outcome)
	}
	if len(report.Controls) != 1 || !report.Controls[0].Complete {
		t.Fatalf("control was not closed: %#v", report.Controls)
	}
}
