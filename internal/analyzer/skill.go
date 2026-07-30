package analyzer

import (
	"context"

	"github.com/domehahn/skil/pkg/skil"
)

type Skill struct{}

func NewSkill() *Skill { return &Skill{} }

func (a *Skill) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.skill", Version: "1.0.0",
		Domain: "skill", Subdomain: "trigger",
		Categories:    []string{"skill-security"},
		AnalysisTypes: []string{"skill"}, SupportedTypes: []string{"*"}}
}

func (a *Skill) TaxonomyDomain() string    { return "skill" }
func (a *Skill) TaxonomySubdomain() string { return "trigger" }
func (a *Skill) ControlIDs() []string {
	return []string{"SKILL-001", "SKILL-002", "SKILL-003", "SKILL-004", "SKILL-005", "SKILL-006", "SKILL-007", "SKILL-008"}
}

func (a *Skill) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	return nil, nil
}
