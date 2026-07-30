package analyzer

import (
	"context"

	"github.com/domehahn/skil/pkg/skil"
)

type ToolCapability struct{}

func NewToolCapability() *ToolCapability { return &ToolCapability{} }

func (a *ToolCapability) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.tool-capability", Version: "1.0.0",
		Domain: "tool-capability", Subdomain: "least-privilege",
		Categories:    []string{"tool-security"},
		AnalysisTypes: []string{"tool-capability"}, SupportedTypes: []string{"*"}}
}

func (a *ToolCapability) TaxonomyDomain() string    { return "tool-capability" }
func (a *ToolCapability) TaxonomySubdomain() string { return "least-privilege" }
func (a *ToolCapability) ControlIDs() []string {
	return []string{"TOOL-001", "TOOL-002", "TOOL-003", "TOOL-004", "TOOL-005", "TOOL-006"}
}

func (a *ToolCapability) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	return nil, nil
}
