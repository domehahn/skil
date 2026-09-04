package redteam

import (
	"context"
	"testing"
)

func TestProbeSkill_CleanSkill(t *testing.T) {
	ctx := context.Background()
	report, err := ProbeSkill(ctx, "../../tests/fixtures/clean-skill", nil)
	if err != nil {
		t.Fatalf("unexpected error probing skill: %v", err)
	}

	if report.SkillName != "clean-skill" {
		t.Errorf("expected skill name 'clean-skill', got '%s'", report.SkillName)
	}

	if report.TotalProbes == 0 {
		t.Errorf("expected active probes, got 0")
	}

	if report.VulnerabilityExploitabilityScore >= 1.0 {
		t.Errorf("clean skill should have low exploitability score, got %f", report.VulnerabilityExploitabilityScore)
	}
}
