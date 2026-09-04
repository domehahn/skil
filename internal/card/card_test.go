package card

import (
	"testing"

	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/internal/trust"
	"github.com/domehahn/skil/pkg/skil"
)

func TestGenerateSkillCard(t *testing.T) {
	art := &skil.Artifact{
		Name:    "kubernetes-deployer",
		Version: "1.2.0",
		Digest:  "sha256abc123",
		Builder: "ci-builder",
	}

	assessment := &trust.TrustAssessment{
		TrustScore: trust.TrustScore{
			Score: 92.5,
		},
		TrustLevel:        trust.LevelVerified,
		AdmissionDecision: registry.DecisionAccept,
	}

	caps := registry.CapabilityFingerprint{
		Domain:      []string{"kubernetes"},
		Actions:     []string{"deploy", "rollback"},
		Tools:       []string{"kubectl", "helm"},
		Permissions: []string{"cluster.read", "cluster.write"},
	}

	c := Generate(art, assessment, caps, nil)

	if c.Metadata.Name != "kubernetes-deployer" {
		t.Errorf("Expected name kubernetes-deployer, got %s", c.Metadata.Name)
	}

	if c.Governance.TrustScore != 92.5 {
		t.Errorf("Expected trust score 92.5, got %.1f", c.Governance.TrustScore)
	}

	yamlBytes, err := c.ToYAML()
	if err != nil || len(yamlBytes) == 0 {
		t.Fatalf("Failed to generate YAML skill card: %v", err)
	}

	jsonBytes, err := c.ToJSON()
	if err != nil || len(jsonBytes) == 0 {
		t.Fatalf("Failed to generate JSON skill card: %v", err)
	}

	md := c.ToMarkdown()
	if len(md) == 0 {
		t.Fatalf("Failed to generate Markdown skill card")
	}
}
