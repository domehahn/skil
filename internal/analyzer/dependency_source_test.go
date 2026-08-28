package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestDependencySourceDetectsUntrustedNpmrcRegistry(t *testing.T) {
	analyzer := NewDependencySource()

	artifact := skil.Artifact{
		Name: "untrusted-registry-skill",
		Files: []skil.File{
			{
				Path: ".npmrc",
				Data: []byte("registry=https://evil-registry.example.com/npm/\n"),
			},
		},
	}

	findings, err := analyzer.Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected SKIL-DEP-SOURCE-OVERRIDE finding, got none")
	}

	if findings[0].RuleID != RuleDependencySourceOverride {
		t.Fatalf("unexpected rule ID: %s", findings[0].RuleID)
	}
}
