package evalharness

import (
	"context"
	"testing"
)

func TestRunEvaluation_CleanSkill(t *testing.T) {
	ctx := context.Background()
	report, err := RunEvaluation(ctx, "../../tests/fixtures/clean-skill", nil)
	if err != nil {
		t.Fatalf("unexpected error running evaluation: %v", err)
	}

	if report.SkillName != "clean-skill" {
		t.Errorf("expected skill name 'clean-skill', got '%s'", report.SkillName)
	}

	if report.PassAt1 <= 0.0 {
		t.Errorf("expected positive PassAt1 score, got %f", report.PassAt1)
	}

	if len(report.Results) == 0 {
		t.Errorf("expected evaluation test results, got 0")
	}
}
