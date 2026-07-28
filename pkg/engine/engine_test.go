package engine

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

type external struct{}

func (external) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "example.external", Version: "1.0.0", AnalysisTypes: []string{"external"}}
}
func (external) Analyze(context.Context, skil.AnalysisContext) ([]skil.Finding, error) {
	return nil, nil
}

func TestExternalAnalyzerRegistration(t *testing.T) {
	registry := New(nil)
	if err := registry.Register(external{}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(external{}); err == nil {
		t.Fatal("expected duplicate rejection")
	}
	result, err := registry.Scan(context.Background(), skil.AnalysisContext{Artifact: skil.Artifact{Name: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Coverage["external"] != skil.CoverageCompleted {
		t.Fatalf("%#v", result.Coverage)
	}
}
