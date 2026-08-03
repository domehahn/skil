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

type diagnosticSemanticProvider struct{}

func (*diagnosticSemanticProvider) ID() string { return "diagnostic-test" }
func (*diagnosticSemanticProvider) AnalyzeUntrusted(context.Context, skil.SemanticRequest) ([]skil.Finding, error) {
	return nil, nil
}
func (*diagnosticSemanticProvider) AnalyzeUntrustedDetailed(context.Context, skil.SemanticRequest) (skil.SemanticAnalysis, error) {
	return skil.SemanticAnalysis{Diagnostics: skil.SemanticDiagnostics{
		Rejected: 1,
		Errors:   []skil.SemanticValidationError{{Index: 0, Message: "has invalid severity"}},
	}}, nil
}

func TestSemanticSuiteMarksRejectedProviderOutputDegraded(t *testing.T) {
	suite, err := NewSemanticSuite(&diagnosticSemanticProvider{})
	if err != nil {
		t.Fatal(err)
	}
	registry := DefaultRegistry(nil)
	if err := registry.Register(suite); err != nil {
		t.Fatal(err)
	}
	result, err := registry.Scan(context.Background(), skil.AnalysisContext{
		Artifact: artifactWith("SKILL.md", "# test"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Coverage["semantic-provider"] != skil.CoverageDegraded {
		t.Fatalf("semantic provider coverage = %q, want degraded", result.Coverage["semantic-provider"])
	}
	if len(result.Diagnostics) == 0 || !strings.Contains(result.Diagnostics[0].Message, "coverage is degraded") {
		t.Fatalf("missing rejection diagnostics: %#v", result.Diagnostics)
	}
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
	if strings.Join(provider.focuses, ",") != "security,intent,quality,policy,meta" {
		t.Fatalf("unexpected semantic passes: %#v", provider.focuses)
	}
}
