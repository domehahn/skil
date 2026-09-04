package contextefficiency

import (
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestAnalyzeEfficiency_RedundantInstructions(t *testing.T) {
	// Repeat phrase 4 times to trigger redundancy detection
	repeatedBlock := "validate kubernetes cluster health status before proceeding "
	content := "# Kubernetes Deployer\n\n" + strings.Repeat(repeatedBlock, 5)

	art := &skil.Artifact{
		Name: "redundant-skill",
		Files: []skil.File{
			{
				Path: "SKILL.md",
				Data: []byte(content),
			},
		},
	}

	report := AnalyzeEfficiency(art)

	if report.TotalTokens == 0 {
		t.Fatalf("Expected non-zero total tokens")
	}

	if report.RedundantTokens == 0 {
		t.Errorf("Expected redundant tokens to be detected")
	}

	if report.PotentialSavingsPercent <= 0 {
		t.Errorf("Expected positive potential savings percentage")
	}
}
