package analyzer

import (
	"context"

	"github.com/domehahn/skil/pkg/skil"
)

type RAGContext struct{}

func NewRAGContext() *RAGContext { return &RAGContext{} }

func (a *RAGContext) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.rag-context", Version: "1.0.0",
		Domain: "rag-context", Subdomain: "indirect-injection",
		Categories:    []string{"rag-security"},
		AnalysisTypes: []string{"rag-context"}, SupportedTypes: []string{"*"}}
}

func (a *RAGContext) TaxonomyDomain() string    { return "rag-context" }
func (a *RAGContext) TaxonomySubdomain() string { return "indirect-injection" }
func (a *RAGContext) ControlIDs() []string {
	return []string{"RAG-001", "RAG-002", "RAG-003", "RAG-004", "RAG-005", "RAG-006"}
}

func (a *RAGContext) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	return nil, nil
}
