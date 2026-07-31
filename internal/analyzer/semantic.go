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
	files, err := semanticFiles(ac)
	if err != nil {
		return nil, err
	}
	var findings []skil.Finding
	for _, focus := range []string{"security", "intent", "quality", "policy"} {
		pass, err := s.provider.AnalyzeUntrusted(ctx, skil.SemanticRequest{
			ArtifactDigest: ac.Artifact.Digest, Files: files, Contract: ac.Contract, Focus: focus, NoTools: true,
		})
		if err != nil {
			return nil, fmt.Errorf("%s semantic pass: %w", focus, err)
		}
		findings = append(findings, pass...)
	}
	synthesis, err := s.provider.AnalyzeUntrusted(ctx, skil.SemanticRequest{
		ArtifactDigest: ac.Artifact.Digest, Files: files, Contract: ac.Contract,
		Focus: "meta", PriorFindings: deduplicateSemantic(findings), NoTools: true,
	})
	if err != nil {
		return nil, fmt.Errorf("meta semantic pass: %w", err)
	}
	findings = append(findings, synthesis...)
	return deduplicateSemantic(findings), nil
}
func (s *Semantic) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "semantic." + s.provider.ID(), Version: "1.0.0",
		Domain: "behavioral", Subdomain: "runtime-observation",
		Categories:    []string{"action-control", "tool-boundary", "activation-integrity", "contract-conformance", "intent-integrity"},
		AnalysisTypes: []string{"semantic", "semantic-provider"}, SupportedTypes: []string{"text"}}
}
func (s *Semantic) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	files, err := semanticFiles(ac)
	if err != nil {
		return nil, err
	}
	return s.provider.AnalyzeUntrusted(ctx, skil.SemanticRequest{
		ArtifactDigest: ac.Artifact.Digest, Files: files, Contract: ac.Contract, NoTools: true,
	})
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
