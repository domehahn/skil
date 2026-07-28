package analyzer

import (
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type Taint struct{}

var (
	assignment = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=`)
	sources    = regexp.MustCompile(`(?i)(os\.environ|os\.getenv|process\.env|input\s*\(|sys\.stdin|requests\.(?:get|post)|fetch\s*\(|readFile|open\s*\([^)]*["']r|tool[_ .]?output|mcp[_ .]?output)`)
	sinks      = []struct {
		name, capability string
		re               *regexp.Regexp
		severity         skil.Severity
	}{
		{"network", "network.outbound", regexp.MustCompile(`(?i)(requests\.(?:post|put)|fetch\s*\(|axios\.post|http\.request)`), skil.SeverityCritical},
		{"execution", "commands.execute", regexp.MustCompile(`(?i)(exec\s*\(|eval\s*\(|subprocess\.|os\.system|child_process\.)`), skil.SeverityCritical},
		{"filesystem write", "filesystem.write", regexp.MustCompile(`(?i)(open\s*\([^)]*["'][wa+]|writeFile)`), skil.SeverityHigh},
		{"log", "external_side_effects", regexp.MustCompile(`(?i)(print\s*\(|log(?:ger)?\.)`), skil.SeverityMedium},
	}
)

func NewTaint() *Taint { return &Taint{} }
func (t *Taint) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.taint", Version: "1.0.0",
		Categories: []string{"data-flow"}, AnalysisTypes: []string{"taint"},
		SupportedTypes: []string{"py", "js", "ts"}}
}

func (t *Taint) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		ext := extension(file.Path)
		if ext != "py" && ext != "js" && ext != "ts" {
			continue
		}
		tainted := map[string]string{}
		for number, line := range lines(file.Data) {
			match := assignment.FindStringSubmatch(line)
			if len(match) > 1 {
				if sources.MatchString(line) {
					tainted[match[1]] = sources.FindString(line)
				} else {
					for variable := range tainted {
						if regexp.MustCompile(`\b` + regexp.QuoteMeta(variable) + `\b`).MatchString(line) {
							tainted[match[1]] = tainted[variable]
						}
					}
				}
			}
			for variable, source := range tainted {
				if !regexp.MustCompile(`\b` + regexp.QuoteMeta(variable) + `\b`).MatchString(line) {
					continue
				}
				for _, sink := range sinks {
					if !sink.re.MatchString(line) {
						continue
					}
					rule := RulePattern{Rule: skil.Rule{
						ID:    "SKIL-TAINT-" + strings.ToUpper(strings.ReplaceAll(sink.name, " ", "-")),
						Title: "Tainted data reaches " + sink.name, Category: "data-flow",
						Severity: sink.severity, Description: "Data from " + source + " reaches " + sink.name + ".",
						Analysis: "taint", Remediation: "Validate, constrain, and sanitize data before the sink.",
					}, Confidence: .78}
					f := makeFinding(rule, file, number+1, line)
					f.Evidence["source"] = source
					f.Evidence["variable"] = variable
					f.Evidence["sink"] = sink.name
					f.Evidence["capability"] = sink.capability
					out = append(out, f)
				}
			}
		}
	}
	return out, nil
}
