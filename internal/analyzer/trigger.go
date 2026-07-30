package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

type Trigger struct {
	rules []RulePattern
	nilPatternRule skil.Rule
}

func NewTrigger() *Trigger {
	r := func(id, title, category string, severity skil.Severity, expr, negative, desc, remediation string) RulePattern {
		var neg *regexp.Regexp
		if negative != "" {
			neg = regexp.MustCompile("(?i)" + negative)
		}
		return RulePattern{Rule: skil.Rule{ID: id, Title: title, Category: category, Severity: severity,
			Description: desc, Analysis: "trigger", AppliesTo: []string{"yaml", "yml", "md", "txt"},
			Remediation: remediation}, Pattern: regexp.MustCompile("(?i)" + expr), Negative: neg, Confidence: .9}
	}
	return &Trigger{
		rules: []RulePattern{
			r("SKIL-TRIGGER-GENERIC", "Overly generic activation phrase", "activation-integrity", skil.SeverityMedium,
				`(?:trigger|invoke|activate|run)\s+(?:on|for|when|with)?\s*[:\s]\s*(?:help|code|file|task|question|please|run|go|start|execute|analyze|check|test|scan|review|update|fix)\b`,
				`(?:do\s+not|avoid|prevent|example)`,
				"A trigger phrase is a common word that increases unintended activation risk.",
				"Use a narrow, domain-specific trigger phrase."),
			r("SKIL-TRIGGER-SHADOW", "Trusted trigger shadowing", "activation-integrity", skil.SeverityHigh,
				`(?:trigger|invoke|activate|run)\s+(?:on|for|when|with)?\s*[:\s]\s*(?:/?(?:deploy|rollback|publish|delete|remove|admin|sudo|su|reboot|shutdown|docker|kubectl))\b`,
				`(?:do\s+not|never|avoid|prevent|example)`,
				"A trigger shadows a built-in or commonly trusted command.",
				"Use a unique explicit trigger that does not shadow existing commands."),
		},
		nilPatternRule: skil.Rule{ID: "SKIL-TRIGGER-LOCK-DIFF", Title: "Trigger surface changed from lock", Category: "activation-integrity", Severity: skil.SeverityHigh,
			Analysis: "trigger", AppliesTo: []string{"yaml", "yml", "lock"},
			Description: "The declared trigger set differs from the reviewed baseline or lock.",
			Remediation: "Re-review triggers and update the lock."},
	}
}

func (a *Trigger) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.trigger", Version: "1.0.0",
		Domain: "skill", Subdomain: "trigger",
		Categories:    []string{"activation-integrity"},
		AnalysisTypes: []string{"trigger"}, SupportedTypes: []string{"yaml", "yml", "md", "txt"}}
}

func (a *Trigger) Rules() []skil.Rule {
	out := make([]skil.Rule, len(a.rules)+1)
	for i := range a.rules {
		out[i] = a.rules[i].Rule
	}
	out[len(a.rules)] = a.nilPatternRule
	return out
}

func (a *Trigger) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	var declaredTriggers []string
	triggerRE := regexp.MustCompile(`(?i)(?:trigger|triggers|activation)\s*[:=]`)

	for _, file := range ac.Artifact.Files {
		ext := strings.ToLower(extension(file.Path))
		if ext != "yaml" && ext != "yml" && ext != "md" && ext != "txt" {
			continue
		}
		if ext == "yaml" || ext == "yml" {
			triggers := extractTriggerPhrases(file.Data)
			declaredTriggers = append(declaredTriggers, triggers...)

			for _, line := range lines(file.Data) {
				for _, rule := range a.rules {
					if rule.Pattern == nil || rule.Pattern.String() == "" {
						continue
					}
					if rule.Pattern.MatchString(line) && (rule.Negative == nil || !rule.Negative.MatchString(line)) {
						ln := lineOf(file.Data, rule.Pattern)
						out = append(out, makeFinding(rule, file, ln, line))
						break
					}
				}
			}
		}
		if ext == "md" || ext == "txt" {
			for _, rule := range a.rules {
				if rule.Pattern == nil || rule.Pattern.String() == "" {
					continue
				}
				for _, line := range lines(file.Data) {
					if rule.Pattern.MatchString(line) && (rule.Negative == nil || !rule.Negative.MatchString(line)) {
						ln := lineOf(file.Data, rule.Pattern)
						out = append(out, makeFinding(rule, file, ln, line))
						break
					}
				}
			}
		}
		if !triggerRE.Match(file.Data) && (ext == "yaml" || ext == "yml") {
			_ = declaredTriggers
		}
	}

	if len(declaredTriggers) > 0 {
		lockDigest := findTriggerLockDigest(ac.Artifact)
		if lockDigest != "" {
			current := triggerDigest(declaredTriggers)
			if current != lockDigest {
				for _, file := range ac.Artifact.Files {
					if strings.ToLower(extension(file.Path)) == "yaml" || strings.ToLower(extension(file.Path)) == "yml" {
						out = append(out, skil.Finding{
							RuleID:      a.nilPatternRule.ID,
							Title:       a.nilPatternRule.Title,
							Category:    a.nilPatternRule.Category,
							Severity:    a.nilPatternRule.Severity,
							Description: a.nilPatternRule.Description,
							Location:    skil.Location{File: file.Path, StartLine: 1, EndLine: 1},
							Evidence: map[string]interface{}{
								"current_digest": current,
								"locked_digest":  lockDigest,
								"engine":         "builtin.trigger",
							},
							Remediation: a.nilPatternRule.Remediation,
						})
						break
					}
				}
			}
		}
	}

	return out, nil
}

func extractTriggerPhrases(data []byte) []string {
	var doc struct {
		Trigger    interface{} `yaml:"trigger"`
		Triggers   interface{} `yaml:"triggers"`
		Activation interface{} `yaml:"activation"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var phrases []string
	seen := map[string]bool{}

	add := func(v interface{}) {
		switch val := v.(type) {
		case string:
			if !seen[val] {
				phrases = append(phrases, val)
				seen[val] = true
			}
		case []interface{}:
			for _, item := range val {
				if s, ok := item.(string); ok && !seen[s] {
					phrases = append(phrases, s)
					seen[s] = true
				}
			}
		}
	}
	add(doc.Trigger)
	add(doc.Triggers)
	add(doc.Activation)
	return phrases
}

func triggerDigest(triggers []string) string {
	sorted := make([]string, len(triggers))
	copy(sorted, triggers)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])
}

func findTriggerLockDigest(art skil.Artifact) string {
	for _, file := range art.Files {
		base := strings.ToLower(filepath.Base(file.Path))
		if base == "agent-skills.lock" || strings.Contains(base, "trigger") && strings.HasSuffix(base, ".lock") {
			var lock struct {
				TriggersDigest string `yaml:"triggers_digest" json:"triggers_digest"`
			}
			if err := yaml.Unmarshal(file.Data, &lock); err == nil && lock.TriggersDigest != "" {
				return lock.TriggersDigest
			}
		}
	}
	return ""
}
