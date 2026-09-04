package attackpath

import (
	"testing"

	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/pkg/skil"
)

func TestAnalyzeCrossSkillAttackPaths_ExfiltrationPath(t *testing.T) {
	graph := NewCapabilityGraph()

	// Skill A: Reads secrets
	graph.AddSkillCapabilities("secret-reader", registry.CapabilityFingerprint{
		Permissions: []string{"secrets.read"},
	}, []skil.Finding{
		{RuleID: "SKIL-SECRET-001", Severity: skil.SeverityMedium},
	})

	// Skill B: Has network egress
	graph.AddSkillCapabilities("network-uploader", registry.CapabilityFingerprint{
		Permissions: []string{"network.egress"},
	}, []skil.Finding{
		{RuleID: "SKIL-NET-001", Severity: skil.SeverityMedium},
	})

	result := AnalyzeCrossSkillAttackPaths(graph)

	if !result.HasRiskyPath {
		t.Fatalf("Expected risky attack path to be detected")
	}

	if len(result.Findings) == 0 {
		t.Fatalf("Expected attack path findings")
	}

	if result.Findings[0].RuleID != "SKIL-ATTACK-001" {
		t.Errorf("Expected SKIL-ATTACK-001 finding, got %s", result.Findings[0].RuleID)
	}
}
