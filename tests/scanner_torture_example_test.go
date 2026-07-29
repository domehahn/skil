package tests

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/pkg/skil"
)

func TestScannerTortureExampleExercisesNativeControls(t *testing.T) {
	source := filepath.Join("..", "examples", "scanner-torture-skill")
	loaded, err := artifact.Load(source, artifact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := analyzer.DefaultRegistry(nil).Scan(context.Background(), skil.AnalysisContext{Artifact: loaded})
	if err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range []string{
		"SKIL-PI-001",
		"SKIL-EX-001",
		"SKIL-PY-001",
		"SKIL-TAINT-NETWORK",
		"SKIL-MCP-001",
		"SKIL-MCP-002",
		"SKIL-MCP-003",
		"SKIL-UNI-001",
	} {
		if !tortureHasRule(result.Findings, ruleID) {
			t.Errorf("scanner torture example did not emit %s", ruleID)
		}
	}
	if result.Status != skil.StatusFail || result.Completeness.Completeness != 1 {
		t.Fatalf("unexpected torture scan result: status=%s completeness=%#v", result.Status, result.Completeness)
	}
}

func tortureHasRule(findings []skil.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
