package eval

import (
	"errors"
	"fmt"
)

// FamilyBenchmarkMetrics captures reproducible detection and completeness metrics
// for a single attack family or rule pack in a regression gate run.
type FamilyBenchmarkMetrics struct {
	Family              string  `json:"family"`
	Precision           float64 `json:"precision"`
	Recall              float64 `json:"recall"`
	FalsePositiveRate   float64 `json:"false_positive_rate"`
	FalseCompleteRate   float64 `json:"false_complete_rate"`
	DeterminismVerified bool    `json:"determinism_verified"`
}

// RegressionGatePolicy defines non-negotiable release gate bounds per family.
type RegressionGatePolicy struct {
	MinPrecision         float64 `json:"min_precision"`
	MinRecall            float64 `json:"min_recall"`
	MaxFalsePositiveRate float64 `json:"max_false_positive_rate"`
	MaxFalseCompleteRate float64 `json:"max_false_complete_rate"`
	RequireDeterminism   bool    `json:"require_determinism"`
}

// DefaultRegressionGatePolicy enforces zero false-complete tolerance and
// deterministic output across all benchmark families.
func DefaultRegressionGatePolicy() RegressionGatePolicy {
	return RegressionGatePolicy{
		MinPrecision:         0.90,
		MinRecall:            0.90,
		MaxFalsePositiveRate: 0.05,
		MaxFalseCompleteRate: 0.00,
		RequireDeterminism:   true,
	}
}

// EvaluateFamilyRegressionGate checks every attack family against the regression policy.
func EvaluateFamilyRegressionGate(families []FamilyBenchmarkMetrics, policy RegressionGatePolicy) error {
	if len(families) == 0 {
		return errors.New("regression gate requires at least one benchmark family")
	}
	for _, fam := range families {
		if fam.Family == "" {
			return errors.New("family name is required")
		}
		if policy.RequireDeterminism && !fam.DeterminismVerified {
			return fmt.Errorf("family %q failed determinism verification", fam.Family)
		}
		if fam.FalseCompleteRate > policy.MaxFalseCompleteRate {
			return fmt.Errorf("family %q false-complete rate %.4f exceeds maximum %.4f", fam.Family, fam.FalseCompleteRate, policy.MaxFalseCompleteRate)
		}
		if fam.Precision < policy.MinPrecision {
			return fmt.Errorf("family %q precision %.3f below minimum %.3f", fam.Family, fam.Precision, policy.MinPrecision)
		}
		if fam.Recall < policy.MinRecall {
			return fmt.Errorf("family %q recall %.3f below minimum %.3f", fam.Family, fam.Recall, policy.MinRecall)
		}
		if fam.FalsePositiveRate > policy.MaxFalsePositiveRate {
			return fmt.Errorf("family %q false-positive rate %.3f exceeds maximum %.3f", fam.Family, fam.FalsePositiveRate, policy.MaxFalsePositiveRate)
		}
	}
	return nil
}
