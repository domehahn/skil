package analyzer

import (
	"context"

	"github.com/domehahn/skil/pkg/skil"
)

type AuditEvidence struct{}

func NewAuditEvidence() *AuditEvidence { return &AuditEvidence{} }

func (a *AuditEvidence) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.audit-evidence", Version: "1.0.0",
		Domain: "audit-evidence", Subdomain: "evidence-integrity",
		Categories:    []string{"audit-security"},
		AnalysisTypes: []string{"audit-evidence"}, SupportedTypes: []string{"*"}}
}

func (a *AuditEvidence) TaxonomyDomain() string    { return "audit-evidence" }
func (a *AuditEvidence) TaxonomySubdomain() string { return "evidence-integrity" }
func (a *AuditEvidence) ControlIDs() []string {
	return []string{"AUDIT-001", "AUDIT-002", "AUDIT-003", "AUDIT-004"}
}

func (a *AuditEvidence) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	return nil, nil
}
