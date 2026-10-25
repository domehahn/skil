package eval

import "testing"

func TestEvaluateFamilyRegressionGate(t *testing.T) {
	pol := DefaultRegressionGatePolicy()
	passing := []FamilyBenchmarkMetrics{
		{Family: "encoded-execution", Precision: 0.98, Recall: 0.96, FalsePositiveRate: 0.01, FalseCompleteRate: 0.0, DeterminismVerified: true},
		{Family: "interprocedural-taint", Precision: 0.95, Recall: 0.94, FalsePositiveRate: 0.02, FalseCompleteRate: 0.0, DeterminismVerified: true},
	}
	if err := EvaluateFamilyRegressionGate(passing, pol); err != nil {
		t.Fatalf("expected passing regression gate, got %v", err)
	}

	// Non-zero FalseCompleteRate must fail closed
	falseComplete := []FamilyBenchmarkMetrics{
		{Family: "encoded-execution", Precision: 0.99, Recall: 0.99, FalsePositiveRate: 0.0, FalseCompleteRate: 0.01, DeterminismVerified: true},
	}
	if err := EvaluateFamilyRegressionGate(falseComplete, pol); err == nil {
		t.Fatal("expected regression gate failure when FalseCompleteRate > 0")
	}

	// Non-deterministic family must fail closed
	nonDet := []FamilyBenchmarkMetrics{
		{Family: "encoded-execution", Precision: 0.99, Recall: 0.99, FalsePositiveRate: 0.0, FalseCompleteRate: 0.0, DeterminismVerified: false},
	}
	if err := EvaluateFamilyRegressionGate(nonDet, pol); err == nil {
		t.Fatal("expected regression gate failure when DeterminismVerified is false")
	}
}
