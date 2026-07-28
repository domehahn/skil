package analyzer

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/pkg/skil"
)

func TestSecurityFixtures(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "security"))
	cases := map[string]string{
		"prompt-injection": "SKIL-PI-001", "secret-exfiltration": "SKIL-EX-001",
		"dangerous-subprocess": "SKIL-PY-002", "curl-pipe-bash": "SKIL-SH-001",
		"mcp-poisoned": "SKIL-MCP-001", "unicode-deception": "SKIL-UNI-001",
		"vulnerable-dependency": "SKIL-DEP-001",
	}
	registry := DefaultRegistry(nil)
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			art, err := artifact.Load(filepath.Join(root, name), artifact.Options{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := registry.Scan(context.Background(), skil.AnalysisContext{Artifact: art})
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range result.Findings {
				if finding.RuleID == rule {
					return
				}
			}
			t.Fatalf("expected %s, got %#v", rule, result.Findings)
		})
	}
}

func TestFalsePositiveFixtureIsClean(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "security", "false-positive"))
	art, err := artifact.Load(root, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := DefaultRegistry(nil).Scan(context.Background(), skil.AnalysisContext{Artifact: art})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("unexpected findings: %#v", result.Findings)
	}
}
