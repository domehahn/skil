package analyzer

import (
	"context"

	"github.com/domehahn/skil/pkg/skil"
)

type PolicyEnforcement struct{}

func NewPolicyEnforcement() *PolicyEnforcement { return &PolicyEnforcement{} }

func (a *PolicyEnforcement) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.policy-enforcement", Version: "1.0.0",
		Domain: "policy-enforcement", Subdomain: "domain-policy",
		Categories:    []string{"policy-security"},
		AnalysisTypes: []string{"policy-enforcement"}, SupportedTypes: []string{"*"}}
}

func (a *PolicyEnforcement) TaxonomyDomain() string    { return "policy-enforcement" }
func (a *PolicyEnforcement) TaxonomySubdomain() string { return "domain-policy" }
func (a *PolicyEnforcement) ControlIDs() []string {
	return []string{"POLICY-001", "POLICY-002", "POLICY-003", "POLICY-004"}
}

func (a *PolicyEnforcement) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	return nil, nil
}
