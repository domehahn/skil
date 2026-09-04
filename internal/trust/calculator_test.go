package trust

import (
	"testing"

	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/pkg/skil"
)

func TestEvaluateTrust_CleanVerifiedSkill(t *testing.T) {
	art := &skil.Artifact{
		Name:    "kubernetes-deployer",
		Version: "1.0.0",
		Digest:  "abc123sha256",
	}

	inputs := TrustInputs{
		Artifact:      art,
		Findings:      nil,
		SkillLift:     0.25, // +25%
		PassAtK:       0.95,
		IsSigned:      true,
		HasProvenance: true,
	}

	assessment := EvaluateTrust(inputs, DefaultTrustWeights())

	if assessment.TrustLevel != LevelVerified {
		t.Errorf("Expected TrustLevel VERIFIED, got %s", assessment.TrustLevel)
	}

	if assessment.TrustScore.Score < 90.0 {
		t.Errorf("Expected score >= 90, got %.1f", assessment.TrustScore.Score)
	}

	if assessment.AdmissionDecision != registry.DecisionAccept {
		t.Errorf("Expected DecisionAccept, got %s", assessment.AdmissionDecision)
	}
}

func TestEvaluateTrust_RevokedSkill(t *testing.T) {
	art := &skil.Artifact{
		Name:    "malicious-skill",
		Version: "0.1.0",
	}

	inputs := TrustInputs{
		Artifact:  art,
		IsRevoked: true,
	}

	assessment := EvaluateTrust(inputs, DefaultTrustWeights())

	if assessment.TrustLevel != LevelRevoked {
		t.Errorf("Expected LevelRevoked, got %s", assessment.TrustLevel)
	}

	if assessment.AdmissionDecision != registry.DecisionReject {
		t.Errorf("Expected DecisionReject, got %s", assessment.AdmissionDecision)
	}
}

func TestEvaluateTrust_HighSecurityDeduction(t *testing.T) {
	art := &skil.Artifact{
		Name:    "vulnerable-skill",
		Version: "1.0.0",
	}

	findings := []skil.Finding{
		{
			ID:       "SKIL-SEC-001",
			RuleID:   "SKIL-PI-001",
			Severity: skil.SeverityCritical,
			Message:  "Critical prompt injection detected",
		},
		{
			ID:       "SKIL-SEC-002",
			RuleID:   "SKIL-SH-001",
			Severity: skil.SeverityHigh,
			Message:  "Unsafe shell execution detected",
		},
	}

	inputs := TrustInputs{
		Artifact:      art,
		Findings:      findings,
		IsSigned:      false,
		HasProvenance: false,
	}

	assessment := EvaluateTrust(inputs, DefaultTrustWeights())

	if assessment.AdmissionDecision != registry.DecisionReject {
		t.Errorf("Expected DecisionReject for critical findings, got %s", assessment.AdmissionDecision)
	}

	if assessment.TrustScore.Breakdown.SecurityScore >= 50.0 {
		t.Errorf("Expected low security breakdown score for vulnerable skill, got %.1f", assessment.TrustScore.Breakdown.SecurityScore)
	}
}
