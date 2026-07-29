package analyzer

import (
	"context"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

type semanticProvider struct {
	request skil.SemanticRequest
}

func (s *semanticProvider) ID() string { return "test" }
func (s *semanticProvider) AnalyzeUntrusted(_ context.Context, request skil.SemanticRequest) ([]skil.Finding, error) {
	s.request = request
	return []skil.Finding{}, nil
}

func TestSemanticAnalyzerLabelsDataAndCoverage(t *testing.T) {
	provider := &semanticProvider{}
	item, err := NewSemantic(provider)
	if err != nil {
		t.Fatal(err)
	}
	registry := DefaultRegistry(nil)
	if err := registry.Register(item); err != nil {
		t.Fatal(err)
	}
	artifact := artifactWith("SKILL.md", "untrusted instructions")
	result, err := registry.Scan(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if !provider.request.NoTools || provider.request.Files["SKILL.md"] == "" ||
		result.Coverage["semantic"] != skil.CoverageCompleted {
		t.Fatalf("request=%#v coverage=%#v", provider.request, result.Coverage)
	}
}

type focusProvider struct{ focuses []string }

func (f *focusProvider) ID() string { return "focus-test" }
func (f *focusProvider) AnalyzeUntrusted(_ context.Context, request skil.SemanticRequest) ([]skil.Finding, error) {
	f.focuses = append(f.focuses, request.Focus)
	return nil, nil
}

func TestSemanticSuiteRunsIndependentPasses(t *testing.T) {
	provider := &focusProvider{}
	suite, err := NewSemanticSuite(provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := suite.Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("SKILL.md", "# test")}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(provider.focuses, ",") != "security,intent,quality,meta" {
		t.Fatalf("unexpected semantic passes: %#v", provider.focuses)
	}
}
