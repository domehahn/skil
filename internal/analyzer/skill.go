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

func (a *Skill) Rules() []skil.Rule {
	return []skil.Rule{
		{
			ID: "SKIL-EXEC-ENCODED-CHAIN", Title: "Encoded payload decoded into execution sink",
			Category: "dynamic-execution", Severity: skil.SeverityCritical, Analysis: "execution-chain",
			AppliesTo:   []string{"sh", "bash", "py", "pyw", "md", "yaml", "yml"},
			Description: "An encoded payload (Base64, Base32, hex, or OpenSSL) is decoded and routed directly into a shell or language execution sink.",
			Remediation: "Remove encoded execution chains and use reviewable, plaintext commands.",
		},
		{
			ID: "SKIL-EXFIL-ENV-DUMP", Title: "Whole-environment or credential store exfiltration",
			Category: "data-exfiltration", Severity: skil.SeverityCritical, Analysis: "execution-chain",
			AppliesTo:   []string{"sh", "bash", "py", "pyw", "js", "ts", "md"},
			Description: "The entire environment or a credential store (.env, SSH key, cloud credentials) is dumped and sent to an external network sink.",
			Remediation: "Never dump the full environment or credential files to external endpoints; read only declared configuration variables.",
		},
	}
}

func (a *Skill) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if isText(file) {
			out = append(out, AnalyzeEncodedExecutionAndExfiltration(file)...)
		}
		ext := extension(file.Path)
		if ext == "md" || ext == "markdown" {
			if fm, err := ParseEffectiveFrontmatter(file); err == nil && fm != nil {
				out = append(out, fm.Findings...)
			}
		}
	}
	return out, nil
}
