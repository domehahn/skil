package analyzer

import (
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

const RuleIntentDivergence = "SKIL-INTENT-DIVERGENCE"

type IntentDivergenceAnalyzer struct{}

func NewIntentDivergence() *IntentDivergenceAnalyzer {
	return &IntentDivergenceAnalyzer{}
}

func (a *IntentDivergenceAnalyzer) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.intent-divergence", Version: "1.0.0",
		Domain: "intent-analysis", Subdomain: "trojan-detection",
		Categories:     []string{"trojan-detection", "semantic-divergence"},
		AnalysisTypes:  []string{"intent-analysis"},
		SupportedTypes: []string{"md", "txt", "json", "js", "py"},
	}
}

func (a *IntentDivergenceAnalyzer) Rules() []skil.Rule {
	return []skil.Rule{
		{
			ID: RuleIntentDivergence, Title: "Semantic intent divergence: declared benign utility executes high-risk operations", Category: "trojan-detection",
			Severity: skil.SeverityHigh, Analysis: "intent-analysis", AppliesTo: []string{"md", "txt", "json", "js", "py"},
			Description: "Declared skill intent in documentation does not match actual execution capabilities.",
			Remediation: "Ensure skill description accurately declares shell execution and network access requirements.",
		},
	}
}

var benignKeywords = regexp.MustCompile(`(?i)\b(formatter|linter|pretty-print|calculator|converter|validator|viewer|read-only|helper|utility)\b`)

func (a *IntentDivergenceAnalyzer) Analyze(ctx context.Context, actx skil.AnalysisContext) ([]skil.Finding, error) {
	var findings []skil.Finding
	artifact := actx.Artifact

	var descriptionText string
	var descFile string
	for _, f := range artifact.Files {
		if strings.HasSuffix(strings.ToLower(f.Path), "skill.md") || strings.HasSuffix(strings.ToLower(f.Path), "mcp.json") {
			descriptionText = string(f.Data)
			descFile = f.Path
			break
		}
	}

	if descriptionText == "" {
		return nil, nil
	}

	if !benignKeywords.MatchString(descriptionText) {
		return nil, nil
	}

	hasShellExecution := false
	hasNetworkEgress := false
	var highRiskLocation skil.Location

	for _, f := range artifact.Files {
		content := string(f.Data)
		if strings.Contains(content, "subprocess.run") || strings.Contains(content, "exec.Command") || strings.Contains(content, "system(") || strings.Contains(content, "eval(") {
			hasShellExecution = true
			highRiskLocation = skil.Location{File: f.Path, StartLine: 1, EndLine: 1}
			break
		}
		if strings.Contains(content, "fetch(") || strings.Contains(content, "http.Post") || strings.Contains(content, "requests.post") {
			hasNetworkEgress = true
			highRiskLocation = skil.Location{File: f.Path, StartLine: 1, EndLine: 1}
		}
	}

	if hasShellExecution || hasNetworkEgress {
		riskType := "shell command execution"
		if hasNetworkEgress && !hasShellExecution {
			riskType = "outbound network HTTP calls"
		}

		findings = append(findings, skil.Finding{
			RuleID:      RuleIntentDivergence,
			Severity:    skil.SeverityHigh,
			Title:       "Semantic intent divergence: declared benign utility executes high-risk operations",
			Message:     "Skill description in " + descFile + " claims to be a benign utility/formatter, but code performs " + riskType + ". Potential Trojan or poisoned skill.",
			Description: "Declared skill intent does not match actual execution capabilities.",
			Location:    highRiskLocation,
			Fingerprint: fingerprint(artifact.Name, RuleIntentDivergence, descFile, "1"),
			Remediation: "Ensure skill description accurately declares shell execution and network access requirements.",
		})
	}

	return findings, nil
}
