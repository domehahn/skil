package completeness

import (
	"os"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestWorkLedger_Invariant(t *testing.T) {
	ledger := WorkLedger{
		Scheduled:       10,
		Processed:       6,
		Transformed:     1,
		Skipped:         1,
		Unsupported:     1,
		BudgetExhausted: 0,
		Failed:          1,
	}

	if !ledger.IsValid() {
		t.Errorf("Expected WorkLedger to be valid, but invariant failed: %+v", ledger)
	}

	if ledger.IncompleteCount() != 4 {
		t.Errorf("Expected IncompleteCount to be 4, got %d", ledger.IncompleteCount())
	}

	if ledger.CompletionRatio() != 0.6 {
		t.Errorf("Expected CompletionRatio to be 0.6, got %f", ledger.CompletionRatio())
	}
}

func TestResultCommitProtocol(t *testing.T) {
	rcp := NewResultCommitProtocol()
	rcp.CommitFinding("FINDING-001: Shell injection risk")
	rcp.CommitFinding("FINDING-002: Hardcoded token")

	if len(rcp.CommittedFindings) != 2 {
		t.Fatalf("Expected 2 committed findings, got %d", len(rcp.CommittedFindings))
	}

	rcp.Finalize("TRUNCATED")
	if !rcp.TruncatedOutput {
		t.Errorf("Expected TruncatedOutput to be true")
	}
	if !rcp.AnalysisIncomplete {
		t.Errorf("Expected AnalysisIncomplete to be true")
	}
	if !rcp.CommitBeforeAck {
		t.Errorf("Expected CommitBeforeAck to be true")
	}
	if !rcp.EvidenceCommitted || rcp.Complete {
		t.Errorf("valid evidence must remain committed while truncated analysis stays incomplete")
	}
}

func TestObserverIdentity(t *testing.T) {
	obs := BuildObserverIdentity("0.7.0", "bin123", "pol456", "ana789", "CLI")

	if obs.SkilVersion != "0.7.0" {
		t.Errorf("Expected version 0.7.0, got %s", obs.SkilVersion)
	}

	if obs.Digest == "" {
		t.Errorf("Expected non-empty observer digest")
	}

	if obs.AttestationIdentity != "skil-observer:0.7.0:CLI" {
		t.Errorf("Unexpected attestation identity: %s", obs.AttestationIdentity)
	}
}

func TestCompletenessBenchmark_Accuracy(t *testing.T) {
	bm := CompletenessAccuracyBenchmark{}

	results := []BenchmarkResult{
		{
			FixtureName:   "exact-skill",
			ExpectedClass: ClassFull,
			ActualClass:   ClassFull,
		},
		{
			FixtureName:   "dynamic-wrapper",
			ExpectedClass: ClassPartial,
			ActualClass:   ClassPartial,
		},
		{
			FixtureName:   "false-complete-fixture",
			ExpectedClass: ClassPartial,
			ActualClass:   ClassFull, // False complete!
		},
	}

	fcr := bm.CalculateFalseCompleteRate(results)
	if fcr != 1.0/3.0 {
		t.Errorf("Expected False Complete Rate to be 0.3333, got %f", fcr)
	}
}

func TestAnalyzeCompleteness_Execution(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "skil-completeness-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	findings := []skil.Finding{
		{
			ID:       "SKIL-DYNAMIC-001",
			RuleID:   "DYNAMIC_EXEC",
			Category: "DYNAMIC_EXECUTION",
			Severity: skil.SeverityMedium,
			Message:  "Dynamic execution via eval",
		},
	}

	report, err := AnalyzeCompleteness(tmpDir, findings)
	if err != nil {
		t.Fatalf("AnalyzeCompleteness failed: %v", err)
	}

	if report.Classification != ClassPartial {
		t.Errorf("Expected ClassPartial for dynamic execution finding, got %s", report.Classification)
	}

	if len(report.Resolutions) == 0 {
		t.Errorf("Expected non-empty resolution evidence")
	}

	if !report.WorkLedger.IsValid() {
		t.Errorf("Work ledger failed invariant check")
	}
}
