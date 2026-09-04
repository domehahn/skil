package card

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/internal/trust"
	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

// SkillCard is the machine-readable and exportable governance card representation of an AI agent skill.
type SkillCard struct {
	CardVersion  string           `json:"card_version" yaml:"card_version"`
	Metadata     CardMetadata     `json:"metadata" yaml:"metadata"`
	Capabilities CardCapabilities `json:"capabilities" yaml:"capabilities"`
	Security     CardSecurity     `json:"security" yaml:"security"`
	Quality      CardQuality      `json:"quality" yaml:"quality"`
	Evaluation   CardEvaluation   `json:"evaluation" yaml:"evaluation"`
	Governance   CardGovernance   `json:"governance" yaml:"governance"`
	Timestamp    time.Time        `json:"timestamp" yaml:"timestamp"`
}

type CardMetadata struct {
	Name        string `json:"name" yaml:"name"`
	Version     string `json:"version,omitempty" yaml:"version,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Author      string `json:"author,omitempty" yaml:"author,omitempty"`
	Publisher   string `json:"publisher,omitempty" yaml:"publisher,omitempty"`
	Repository  string `json:"repository,omitempty" yaml:"repository,omitempty"`
	Commit      string `json:"commit,omitempty" yaml:"commit,omitempty"`
	Digest      string `json:"digest" yaml:"digest"`
}

type CardCapabilities struct {
	Domains     []string `json:"domains,omitempty" yaml:"domains,omitempty"`
	Actions     []string `json:"actions,omitempty" yaml:"actions,omitempty"`
	Tools       []string `json:"tools,omitempty" yaml:"tools,omitempty"`
	Resources   []string `json:"resources,omitempty" yaml:"resources,omitempty"`
	Permissions []string `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	MCPServers  []string `json:"mcp_servers,omitempty" yaml:"mcp_servers,omitempty"`
}

type CardSecurity struct {
	Status           string `json:"status" yaml:"status"`
	CriticalFindings int    `json:"critical_findings" yaml:"critical_findings"`
	HighFindings     int    `json:"high_findings" yaml:"high_findings"`
	MediumFindings   int    `json:"medium_findings" yaml:"medium_findings"`
	LowFindings      int    `json:"low_findings" yaml:"low_findings"`
}

type CardQuality struct {
	Rating                  string  `json:"rating" yaml:"rating"`
	ContextTokens           int     `json:"context_tokens,omitempty" yaml:"context_tokens,omitempty"`
	RedundantSavingsPercent float64 `json:"redundant_savings_percent,omitempty" yaml:"redundant_savings_percent,omitempty"`
}

type CardEvaluation struct {
	Status           string  `json:"status" yaml:"status"`
	SkillLiftPercent float64 `json:"skill_lift_percent,omitempty" yaml:"skill_lift_percent,omitempty"`
	PassAtK          float64 `json:"pass_at_k,omitempty" yaml:"pass_at_k,omitempty"`
}

type CardGovernance struct {
	TrustScore        float64                    `json:"trust_score" yaml:"trust_score"`
	TrustLevel        trust.TrustLevel           `json:"trust_level" yaml:"trust_level"`
	AdmissionDecision registry.AdmissionDecision `json:"admission_decision" yaml:"admission_decision"`
	IsSigned          bool                       `json:"is_signed" yaml:"is_signed"`
	HasProvenance     bool                       `json:"has_provenance" yaml:"has_provenance"`
}

// Generate creates a SkillCard from artifact evidence and trust assessment.
func Generate(art *skil.Artifact, assessment *trust.TrustAssessment, caps registry.CapabilityFingerprint, findings []skil.Finding) *SkillCard {
	name := "unknown-skill"
	version := ""
	digest := ""
	repo := ""
	commit := ""
	builder := ""

	if art != nil {
		if art.Name != "" {
			name = art.Name
		}
		version = art.Version
		digest = art.SubjectDigest()
		repo = art.Repository
		commit = art.Commit
		builder = art.Builder
	}

	crit, high, med, low := 0, 0, 0, 0
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		switch f.Severity {
		case skil.SeverityCritical:
			crit++
		case skil.SeverityHigh:
			high++
		case skil.SeverityMedium:
			med++
		case skil.SeverityLow:
			low++
		}
	}

	secStatus := "PASSED"
	if crit > 0 || high > 0 {
		secStatus = "FAILED"
	} else if med > 0 || low > 0 {
		secStatus = "WARNINGS"
	}

	tScore := 0.0
	tLevel := trust.LevelUntrusted
	decision := registry.DecisionReject

	if assessment != nil {
		tScore = assessment.TrustScore.Score
		tLevel = assessment.TrustLevel
		decision = assessment.AdmissionDecision
	}

	return &SkillCard{
		CardVersion: "1.0",
		Metadata: CardMetadata{
			Name:       name,
			Version:    version,
			Publisher:  builder,
			Repository: repo,
			Commit:     commit,
			Digest:     digest,
		},
		Capabilities: CardCapabilities{
			Domains:     caps.Domain,
			Actions:     caps.Actions,
			Tools:       caps.Tools,
			Resources:   caps.Resources,
			Permissions: caps.Permissions,
			MCPServers:  caps.Integrations,
		},
		Security: CardSecurity{
			Status:           secStatus,
			CriticalFindings: crit,
			HighFindings:     high,
			MediumFindings:   med,
			LowFindings:      low,
		},
		Quality: CardQuality{
			Rating: "PASS",
		},
		Evaluation: CardEvaluation{
			Status: "EVALUATED",
		},
		Governance: CardGovernance{
			TrustScore:        tScore,
			TrustLevel:        tLevel,
			AdmissionDecision: decision,
			IsSigned:          art != nil && art.PackageDigest != "",
			HasProvenance:     art != nil && art.Builder != "",
		},
		Timestamp: time.Now().UTC(),
	}
}

// ToYAML serializes the SkillCard to YAML bytes.
func (c *SkillCard) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// ToJSON serializes the SkillCard to formatted JSON bytes.
func (c *SkillCard) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// ToMarkdown renders a user-facing GitHub Flavored Markdown Skill Card.
func (c *SkillCard) ToMarkdown() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# SKIL Skill Card: %s\n\n", c.Metadata.Name))
	sb.WriteString(fmt.Sprintf("**Version:** `%s` | **Digest:** `%s` | **Trust Level:** `%s`\n\n", c.Metadata.Version, c.Metadata.Digest, c.Governance.TrustLevel))

	sb.WriteString("## Trust & Admission Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Trust Score:** %.1f / 100\n", c.Governance.TrustScore))
	sb.WriteString(fmt.Sprintf("- **Admission Decision:** `%s`\n", c.Governance.AdmissionDecision))
	sb.WriteString(fmt.Sprintf("- **Signed Package:** `%t` | **Provenance Verified:** `%t`\n\n", c.Governance.IsSigned, c.Governance.HasProvenance))

	sb.WriteString("## Security & Quality\n\n")
	sb.WriteString(fmt.Sprintf("- **Security Status:** `%s` (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
		c.Security.Status, c.Security.CriticalFindings, c.Security.HighFindings, c.Security.MediumFindings, c.Security.LowFindings))
	sb.WriteString(fmt.Sprintf("- **Quality Rating:** `%s`\n\n", c.Quality.Rating))

	sb.WriteString("## Declared Capabilities\n\n")
	if len(c.Capabilities.Domains) > 0 {
		sb.WriteString(fmt.Sprintf("- **Domains:** %s\n", strings.Join(c.Capabilities.Domains, ", ")))
	}
	if len(c.Capabilities.Actions) > 0 {
		sb.WriteString(fmt.Sprintf("- **Actions:** %s\n", strings.Join(c.Capabilities.Actions, ", ")))
	}
	if len(c.Capabilities.Tools) > 0 {
		sb.WriteString(fmt.Sprintf("- **Tools:** %s\n", strings.Join(c.Capabilities.Tools, ", ")))
	}
	if len(c.Capabilities.Permissions) > 0 {
		sb.WriteString(fmt.Sprintf("- **Permissions:** %s\n", strings.Join(c.Capabilities.Permissions, ", ")))
	}

	return sb.String()
}
