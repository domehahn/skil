package verification

import (
	"math/rand"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/pkg/skil"
)

// TestRiskScorePermutationInvariance proves that Risk(F) == Risk(shuffle(F)).
func TestRiskScorePermutationInvariance(t *testing.T) {
	findings := []skil.Finding{
		{RuleID: "SKIL-SH-001", Severity: skil.SeverityHigh},
		{RuleID: "SKIL-SEC-001", Severity: skil.SeverityMedium},
		{RuleID: "SKIL-DEP-001", Severity: skil.SeverityLow},
	}
	coverage := map[string]skil.CoverageState{"ast": skil.CoverageCompleted, "taint": skil.CoverageCompleted}

	sev1, score1, _ := analyzer.Risk(findings, coverage)

	// Shuffle findings
	shuffled := make([]skil.Finding, len(findings))
	copy(shuffled, findings)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	sev2, score2, _ := analyzer.Risk(shuffled, coverage)

	if score1 != score2 || sev1 != sev2 {
		t.Fatalf("Risk score is not permutation invariant: original=(%s, %d), shuffled=(%s, %d)", sev1, score1, sev2, score2)
	}
}

// TestRiskScoreMonotonicity proves that adding a finding never decreases the risk score.
func TestRiskScoreMonotonicity(t *testing.T) {
	findings := []skil.Finding{
		{RuleID: "SKIL-SH-001", Severity: skil.SeverityMedium},
	}
	coverage := map[string]skil.CoverageState{"ast": skil.CoverageCompleted, "taint": skil.CoverageCompleted}

	_, score1, _ := analyzer.Risk(findings, coverage)

	moreFindings := append(findings, skil.Finding{RuleID: "SKIL-SEC-001", Severity: skil.SeverityHigh})
	_, score2, _ := analyzer.Risk(moreFindings, coverage)

	if score2 < score1 {
		t.Fatalf("Risk score monotonicity violated: score decreased from %d to %d", score1, score2)
	}
}
