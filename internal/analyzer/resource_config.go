package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

type ResourceConfig struct{ rules []RulePattern }

func NewResourceConfig() *ResourceConfig {
	r := func(id, title, category string, severity skil.Severity, expr, negative, desc, remediation string) RulePattern {
		var neg *regexp.Regexp
		if negative != "" {
			neg = regexp.MustCompile("(?i)" + negative)
		}
		return RulePattern{Rule: skil.Rule{ID: id, Title: title, Category: category, Severity: severity,
			Description: desc, Analysis: "resource-config", AppliesTo: []string{"yaml", "yml", "json", "py", "js", "ts", "text"},
			Remediation: remediation}, Pattern: regexp.MustCompile("(?i)" + expr), Negative: neg, Confidence: .9}
	}
	return &ResourceConfig{rules: []RulePattern{
		r("SKIL-RESOURCE-UNLIMITED", "Unlimited resource allocation", "resource-boundary", skil.SeverityMedium,
			`(?:max_?tokens|max_?output|max_?length|max_?iterations?|max_?steps?|n_?steps?|max_?depth)\s*(?::|=|\s+)\s*(?:null|None|none|0|-1|infinity|unlimited|false)`,
			`(?:do\s+not|never|avoid|prevent|detect|must\s+not)\s+(?:use\s+)?(?:unlimited|infinite|unbounded)`,
			"A resource limit is set to None, null, or infinity, allowing unbounded consumption.",
			"Set finite resource limits aligned with the operational budget."),
		r("SKIL-RESOURCE-TIMEOUT", "Disabled timeout or retry bound", "resource-boundary", skil.SeverityMedium,
			`(?:timeout|time_?out|retry_?limit|max_?retries?|max_?attempts?)\s*(?::|=|\s+)\s*(?:null|None|none|0|-1|infinity|unlimited|false)`,
			`(?:must|require|enforce)\s+(?:a\s+)?(?:timeout|retry|limit)`,
			"A timeout or retry parameter is unset or unbounded, risking resource starvation.",
			"Set explicit finite timeouts and retry limits."),
		r("SKIL-RESOURCE-UNBOUNDED-LOOP", "Unbounded loop or recursion risk", "resource-boundary", skil.SeverityHigh,
			`\b(?:while\s+(?:true|1|yes)\b|for\s+\w+\s+in\s+iter\(|loop\s+do\b\s*|until\s+false\b)|(?:retry|poll|wait)\s*(?::|=|\s+)(?:-1|infinity|unlimited|forever|never)`,
			`(?:do\s+not|never|avoid|prevent)\s+(?:use\s+)?(?:unbounded|infinite|forever)`,
			"Code or configuration allows unbounded retries, polling, or recursion without a termination condition.",
			"Add max-iterations, timeout, or circuit-breaker to bound the loop."),
	}}
}

func (a *ResourceConfig) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.resource-config", Version: "1.0.0",
		Domain: "skill", Subdomain: "scope",
		Categories:    []string{"secure-defaults", "resource-boundary"},
		AnalysisTypes: []string{"resource-config"}, SupportedTypes: []string{"yaml", "yml", "json", "py", "js", "ts", "text"}}
}

func (a *ResourceConfig) Rules() []skil.Rule {
	out := make([]skil.Rule, len(a.rules))
	for i := range a.rules {
		out[i] = a.rules[i].Rule
	}
	return out
}

func (a *ResourceConfig) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		for _, rule := range a.rules {
			if rule.Pattern == nil {
				continue
			}
			matches := rule.Pattern.FindAllString(string(file.Data), -1)
			for _, match := range matches {
				negated := rule.Negative != nil && rule.Negative.MatchString(string(file.Data))
				if negated {
					continue
				}
				ln := lineOf(file.Data, rule.Pattern)
				f := makeFinding(rule, file, ln, match)
				f.Evidence["match_type"] = rule.Rule.ID
				out = append(out, f)
			}
		}
		ext := strings.ToLower(extension(file.Path))
		if ext == "yaml" || ext == "yml" {
			out = append(out, a.scanYAMLResources(file, out)...)
		}
	}
	return out, nil
}

func (a *ResourceConfig) scanYAMLResources(file skil.File, _ []skil.Finding) []skil.Finding {
	var doc map[string]interface{}
	data := string(file.Data)
	if err := yaml.Unmarshal([]byte(data), &doc); err != nil {
		return nil
	}
	var out []skil.Finding
	flattenYAML("", doc, func(path string, value interface{}) {
		s, ok := value.(string)
		if !ok {
			return
		}
		for _, rule := range a.rules {
			if rule.Pattern == nil {
				continue
			}
			combined := path + ": " + s
			if rule.Pattern.MatchString(combined) {
				negated := rule.Negative != nil && rule.Negative.MatchString(combined)
				if negated {
					continue
				}
				f := makeFinding(rule, file, 1, truncate(combined, 160))
				f.Evidence["config_path"] = path
				out = append(out, f)
				break
			}
		}
	})
	return out
}

func flattenYAML(prefix string, v interface{}, fn func(string, interface{})) {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, v := range val {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			fn(path, v)
			flattenYAML(path, v, fn)
		}
	case []interface{}:
		for i, v := range val {
			path := fmt.Sprintf("%s[%d]", prefix, i)
			fn(path, v)
			flattenYAML(path, v, fn)
		}
	}
}
