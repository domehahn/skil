package eval

import (
	"fmt"
)

// BenchmarkQualityThresholds configures release gate quality metrics.
type BenchmarkQualityThresholds struct {
	MinPrecision    float64 `json:"min_precision"`
	MinRecall       float64 `json:"min_recall"`
	MaxFalsePos     int     `json:"max_false_positives"`
	MinRuleCoverage float64 `json:"min_rule_coverage"`
}

// DefaultQualityThresholds returns the standard production release quality thresholds.
func DefaultQualityThresholds() BenchmarkQualityThresholds {
	return BenchmarkQualityThresholds{
		MinPrecision:    0.90,
		MinRecall:       0.95,
		MaxFalsePos:     2,
		MinRuleCoverage: 0.85,
	}
}

type BenchmarkRunSummary struct {
	TotalCases     int     `json:"total_cases"`
	TruePositives  int     `json:"true_positives"`
	FalsePositives int     `json:"false_positives"`
	TrueNegatives  int     `json:"true_negatives"`
	FalseNegatives int     `json:"false_negatives"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
	F1Score        float64 `json:"f1_score"`
	RuleCoverage   float64 `json:"rule_coverage"`
}

// EvaluateBenchmarkQualityGate validates a benchmark summary against release quality thresholds.
func EvaluateBenchmarkQualityGate(summary BenchmarkRunSummary, thresholds BenchmarkQualityThresholds) error {
	if summary.Precision < thresholds.MinPrecision {
		return fmt.Errorf("benchmark precision regression: %.3f < minimum required %.3f", summary.Precision, thresholds.MinPrecision)
	}

	if summary.Recall < thresholds.MinRecall {
		return fmt.Errorf("benchmark recall regression: %.3f < minimum required %.3f", summary.Recall, thresholds.MinRecall)
	}

	if summary.FalsePositives > thresholds.MaxFalsePos {
		return fmt.Errorf("benchmark false positive regression: %d > maximum allowed %d", summary.FalsePositives, thresholds.MaxFalsePos)
	}

	if summary.RuleCoverage < thresholds.MinRuleCoverage {
		return fmt.Errorf("benchmark rule coverage regression: %.3f < minimum required %.3f", summary.RuleCoverage, thresholds.MinRuleCoverage)
	}

	return nil
}
