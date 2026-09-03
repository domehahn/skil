package analyzer

import (
	"context"
	"fmt"

	"github.com/domehahn/skil/pkg/skil"
)

const maxSemanticBytes = 1 << 20

type Semantic struct{ provider skil.SemanticProvider }
type SemanticSuite struct{ provider skil.SemanticProvider }

func NewSemantic(provider skil.SemanticProvider) (*Semantic, error) {
	if provider == nil {
		return nil, fmt.Errorf("semantic provider is required")
	}
	return &Semantic{provider: provider}, nil
}

func NewSemanticSuite(provider skil.SemanticProvider) (*SemanticSuite, error) {
	if provider == nil {
		return nil, fmt.Errorf("semantic provider is required")
	}
	return &SemanticSuite{provider: provider}, nil
}

func (s *SemanticSuite) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "semantic-suite." + s.provider.ID(), Version: "1.0.0",
		Domain: "behavioral", Subdomain: "runtime-observation",
		Categories:    []string{"semantic-security", "intent-integrity", "quality-policy", "semantic-composition"},
		AnalysisTypes: []string{"semantic", "semantic-provider"}, SupportedTypes: []string{"text"}}
}

func (s *SemanticSuite) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	result, err := s.AnalyzeResult(ctx, ac)
	return result.Findings, err
}

func (s *SemanticSuite) AnalyzeResult(ctx context.Context, ac skil.AnalysisContext) (skil.AnalyzerResult, error) {
	files, err := semanticFiles(ac)
	if err != nil {
		return skil.AnalyzerResult{}, err
	}
	var findings []skil.Finding
	var diagnostics []skil.Diagnostic
	degraded := false
	for _, focus := range []string{"security", "intent", "quality", "policy"} {
		pass, passDiagnostics, err := analyzeSemanticPass(ctx, s.provider, skil.SemanticRequest{
			ArtifactDigest: ac.Artifact.Digest, Files: files, Contract: ac.Contract, Focus: focus, NoTools: true,
		})
		if err != nil {
			return skil.AnalyzerResult{}, fmt.Errorf("%s semantic pass: %w", focus, err)
		}
		findings = append(findings, pass...)
		diagnostics = append(diagnostics, semanticDiagnostics(focus, s.provider.ID(), passDiagnostics)...)
		degraded = degraded || passDiagnostics.Rejected > 0
	}
	synthesis, synthesisDiagnostics, err := analyzeSemanticPass(ctx, s.provider, skil.SemanticRequest{
		ArtifactDigest: ac.Artifact.Digest, Files: files, Contract: ac.Contract,
		Focus: "meta", PriorFindings: deduplicateSemantic(findings), NoTools: true,
	})
	if err != nil {
		return skil.AnalyzerResult{}, fmt.Errorf("meta semantic pass: %w", err)
	}
	findings = append(findings, synthesis...)
	diagnostics = append(diagnostics, semanticDiagnostics("meta", s.provider.ID(), synthesisDiagnostics)...)
	degraded = degraded || synthesisDiagnostics.Rejected > 0
	coverage := map[string]skil.CoverageState{}
	if degraded {
		coverage["semantic-provider"] = skil.CoverageDegraded
	}
	return skil.AnalyzerResult{
		Findings: deduplicateSemantic(findings), Diagnostics: diagnostics, Coverage: coverage,
	}, nil
}
func (s *Semantic) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "semantic." + s.provider.ID(), Version: "1.0.0",
		Domain: "behavioral", Subdomain: "runtime-observation",
		Categories:    []string{"action-control", "tool-boundary", "activation-integrity", "contract-conformance", "intent-integrity"},
		AnalysisTypes: []string{"semantic", "semantic-provider"}, SupportedTypes: []string{"text"}}
}
func (s *Semantic) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	result, err := s.AnalyzeResult(ctx, ac)
	return result.Findings, err
}

func (s *Semantic) AnalyzeResult(ctx context.Context, ac skil.AnalysisContext) (skil.AnalyzerResult, error) {
	files, err := semanticFiles(ac)
	if err != nil {
		return skil.AnalyzerResult{}, err
	}
	findings, providerDiagnostics, err := analyzeSemanticPass(ctx, s.provider, skil.SemanticRequest{
		ArtifactDigest: ac.Artifact.Digest, Files: files, Contract: ac.Contract, NoTools: true,
	})
	if err != nil {
		return skil.AnalyzerResult{}, err
	}
	coverage := map[string]skil.CoverageState{}
	if providerDiagnostics.Rejected > 0 {
		coverage["semantic-provider"] = skil.CoverageDegraded
	}
	return skil.AnalyzerResult{
		Findings:    findings,
		Diagnostics: semanticDiagnostics("all", s.provider.ID(), providerDiagnostics),
		Coverage:    coverage,
	}, nil
}

func analyzeSemanticPass(ctx context.Context, provider skil.SemanticProvider, request skil.SemanticRequest) ([]skil.Finding, skil.SemanticDiagnostics, error) {
	if detailed, ok := provider.(skil.DiagnosticSemanticProvider); ok {
		result, err := detailed.AnalyzeUntrustedDetailed(ctx, request)
		return result.Findings, result.Diagnostics, err
	}
	findings, err := provider.AnalyzeUntrusted(ctx, request)
	return findings, skil.SemanticDiagnostics{Accepted: len(findings)}, err
}

func semanticDiagnostics(focus, provider string, diagnostics skil.SemanticDiagnostics) []skil.Diagnostic {
	if diagnostics.Rejected == 0 {
		return nil
	}
	summary := fmt.Sprintf("%s semantic pass from %s accepted %d findings and rejected %d; coverage is degraded",
		focus, provider, diagnostics.Accepted, diagnostics.Rejected)
	if diagnostics.Incomplete {
		summary = fmt.Sprintf("%s semantic pass from %s was incomplete (provider/response problem, not a per-finding rejection); coverage is degraded",
			focus, provider)
	}
	out := []skil.Diagnostic{{Component: "semantic-provider", Level: "warning", Message: summary}}
	for _, validationError := range diagnostics.Errors {
		if validationError.Index < 0 {
			out = append(out, skil.Diagnostic{
				Component: "semantic-provider", Level: "warning",
				Message: fmt.Sprintf("%s semantic pass incomplete: %s", focus, validationError.Message),
			})
			continue
		}
		out = append(out, skil.Diagnostic{
			Component: "semantic-provider", Level: "warning",
			Message: fmt.Sprintf("%s semantic finding %d rejected: %s", focus, validationError.Index, validationError.Message),
		})
	}
	return out
}

func semanticFiles(ac skil.AnalysisContext) (map[string]string, error) {
	files := map[string]string{}
	total := 0
	for _, file := range ac.Artifact.Files {
		if !isText(file) {
			continue
		}
		total += len(file.Data)
		if total > maxSemanticBytes {
			return nil, fmt.Errorf("semantic input exceeds %d-byte transmission limit", maxSemanticBytes)
		}
		files[file.Path] = string(file.Data)
	}
	return files, nil
}

func deduplicateSemantic(findings []skil.Finding) []skil.Finding {
	seen := map[string]bool{}
	out := make([]skil.Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.RuleID + "\x00" + finding.Fingerprint
		if !seen[key] {
			seen[key] = true
			out = append(out, finding)
		}
	}
	return out
}
