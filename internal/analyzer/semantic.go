package analyzer

import (
	"context"
	"fmt"

	"github.com/domehahn/skil/pkg/skil"
)

const maxSemanticBytes = 1 << 20

type Semantic struct{ provider skil.SemanticProvider }

func NewSemantic(provider skil.SemanticProvider) (*Semantic, error) {
	if provider == nil {
		return nil, fmt.Errorf("semantic provider is required")
	}
	return &Semantic{provider: provider}, nil
}
func (s *Semantic) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "semantic." + s.provider.ID(), Version: "1.0.0",
		Categories:    []string{"excessive-agency", "tool-misuse", "trigger-abuse", "capability-mismatch"},
		AnalysisTypes: []string{"semantic"}, SupportedTypes: []string{"text"}}
}
func (s *Semantic) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
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
	return s.provider.AnalyzeUntrusted(ctx, skil.SemanticRequest{
		ArtifactDigest: ac.Artifact.Digest, Files: files, Contract: ac.Contract, NoTools: true,
	})
}
