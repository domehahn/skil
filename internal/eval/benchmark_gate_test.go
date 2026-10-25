package eval

import (
	"testing"
)

func TestEvaluateBenchmarkQualityGate_Passing(t *testing.T) {
	summary := BenchmarkRunSummary{
		TotalCases:     100,
		TruePositives:  50,
		FalsePositives: 1,
		TrueNegatives:  48,
		FalseNegatives: 1,
		Precision:      0.98,
		Recall:         0.98,
		F1Score:        0.98,
		RuleCoverage:   0.90,
	}

	err := EvaluateBenchmarkQualityGate(summary, DefaultQualityThresholds())
	if err != nil {
		t.Errorf("Expected benchmark quality gate to pass, got error: %v", err)
	}
}

func TestEvaluateBenchmarkQualityGate_RecallRegression(t *testing.T) {
	summary := BenchmarkRunSummary{
		TotalCases:     100,
		TruePositives:  40,
		FalsePositives: 1,
		TrueNegatives:  48,
		FalseNegatives: 11,
		Precision:      0.975,
		Recall:         0.784, // Below 0.95 requirement!
		F1Score:        0.87,
		RuleCoverage:   0.90,
	}

	err := EvaluateBenchmarkQualityGate(summary, DefaultQualityThresholds())
	if err == nil {
		t.Errorf("Expected benchmark quality gate failure for recall regression, got pass")
	}
}
