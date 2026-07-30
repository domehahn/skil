package analyzer

import (
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type HiddenInstruction struct{ rules []RulePattern }

func NewHiddenInstruction() *HiddenInstruction {
	r := func(id, title, category string, severity skil.Severity, pattern *regexp.Regexp, confidence float64, desc, remediation string) RulePattern {
		return RulePattern{Rule: skil.Rule{ID: id, Title: title, Category: category, Severity: severity,
			Description: desc, Analysis: "pattern", AppliesTo: []string{"markdown", "text", "html"},
			Remediation: remediation}, Pattern: pattern, Confidence: confidence}
	}
	instructionPayload := regexp.MustCompile(`(?i)<!--[\s\S]{0,40}(?:ignore|override|never\s+refuse|you\s+must|always\s+comply|unrestricted|jailbreak|disregard|system\s+prompt|hidden|secret|do\s+not\s+(?:reveal|tell|warn|alert)|reveal\s+(?:your|system)\s+prompt)`)
	longComment := regexp.MustCompile(`(?i)<!--.{200,}-->`)
	return &HiddenInstruction{rules: []RulePattern{
		r("SKIL-PI-HIDDEN-COMMENT", "Hidden instruction in render-suppressed region", "instruction-integrity", skil.SeverityCritical,
			instructionPayload, .95,
			"An HTML or Markdown comment contains security-sensitive instructions that are invisible when rendered.",
			"Remove hidden instructions or make them visible for review."),
		r("SKIL-PI-SUSPICIOUS-COMMENT", "Render-suppressed region with unusual length", "instruction-integrity", skil.SeverityMedium,
			longComment, .75,
			"An unusually long HTML or Markdown comment may conceal instructions or data.",
			"Review and remove unreasonably large comments."),
	}}
}

func (a *HiddenInstruction) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.hidden-instruction", Version: "1.0.0",
		Domain: "instruction", Subdomain: "prompt-injection",
		Categories:    []string{"instruction-integrity"},
		AnalysisTypes: []string{"pattern"}, SupportedTypes: []string{"md", "txt", "html"}}
}

func (a *HiddenInstruction) Rules() []skil.Rule {
	out := make([]skil.Rule, len(a.rules))
	for i := range a.rules {
		out[i] = a.rules[i].Rule
	}
	return out
}

func (a *HiddenInstruction) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		for _, rule := range a.rules {
			matches := rule.Pattern.FindAllString(string(file.Data), -1)
			for _, match := range matches {
				line := lineOf(file.Data, rule.Pattern)
				f := makeFinding(rule, file, line, match)
				f.Evidence["match_type"] = "comment"
				out = append(out, f)
			}
		}
		blankComment := regexp.MustCompile(`<!--\s*-->|<!---->`)
		count := 0
		for _, line := range strings.Split(string(file.Data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "<!--") && strings.Contains(trimmed, "-->") {
				for _, rule := range a.rules {
					if rule.Pattern.MatchString(trimmed) {
						f := makeFinding(rule, file, count+1, trimmed)
						f.Evidence["match_type"] = "inline-comment"
						out = append(out, f)
					}
				}
			}
			if blankComment.MatchString(trimmed) {
				continue
			}
			count++
		}
	}
	return out, nil
}
