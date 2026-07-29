package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unsafe"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	tree_sitter_typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"

	"github.com/domehahn/skil/pkg/skil"
)

type Taint struct{}

var (
	taintSources = regexp.MustCompile(`(?i)(os\.environ|os\.getenv|process\.env|input\s*\(|sys\.stdin|request\.(?:args|query|body)|readFile|open\s*\([^)]*["']r|tool[_ .-]?output|mcp[_ .-]?output)`)
	sanitizers   = regexp.MustCompile(`(?i)\b(?:sanitize|validate|allowlist|whitelist|escape|urlparse|url\.parse|path\.resolve)\s*\(`)
	identifier   = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)
	taintSinks   = []struct {
		name, capability string
		re               *regexp.Regexp
		severity         skil.Severity
	}{
		{"network", "network.outbound", regexp.MustCompile(`(?i)(requests\.(?:post|put|get)|fetch\s*\(|axios\.(?:post|get)|http\.(?:request|get)|urllib\.request)`), skil.SeverityCritical},
		{"execution", "commands.execute", regexp.MustCompile(`(?i)(exec\s*\(|eval\s*\(|subprocess\.|os\.system|child_process\.)`), skil.SeverityCritical},
		{"filesystem write", "filesystem.write", regexp.MustCompile(`(?i)(open\s*\([^)]*["'][wa+]|writeFile)`), skil.SeverityHigh},
		{"log", "external_side_effects", regexp.MustCompile(`(?i)(print\s*\(|console\.log|log(?:ger)?\.)`), skil.SeverityMedium},
	}
)

type flowAssignment struct {
	targets []string
	value   string
	line    int
}

type flowCall struct {
	text string
	line int
}

func NewTaint() *Taint { return &Taint{} }
func (t *Taint) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.taint", Version: "2.0.0",
		Categories: []string{"data-flow"}, AnalysisTypes: []string{"taint"},
		SupportedTypes: []string{"py", "js", "jsx", "ts", "tsx"}}
}

func (t *Taint) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		language := taintLanguage(extension(file.Path))
		if language == nil {
			continue
		}
		tree, err := parseStructured(ctx, file.Data, language)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		assignments, calls := collectFlowNodes(tree.RootNode(), file.Data)
		tree.Close()
		out = append(out, analyzeFlow(file, assignments, calls)...)
	}
	return out, nil
}

func taintLanguage(ext string) unsafe.Pointer {
	switch ext {
	case "py":
		return tree_sitter_python.Language()
	case "js", "jsx":
		return tree_sitter_javascript.Language()
	case "ts":
		return tree_sitter_typescript.LanguageTypescript()
	case "tsx":
		return tree_sitter_typescript.LanguageTSX()
	default:
		return nil
	}
}

func collectFlowNodes(root *tree_sitter.Node, source []byte) ([]flowAssignment, []flowCall) {
	var assignments []flowAssignment
	var calls []flowCall
	walkNode(root, func(node *tree_sitter.Node) {
		switch node.Kind() {
		case "assignment", "assignment_expression", "variable_declarator":
			left := node.ChildByFieldName("left")
			if left == nil {
				left = node.ChildByFieldName("name")
			}
			right := node.ChildByFieldName("right")
			if right == nil {
				right = node.ChildByFieldName("value")
			}
			if left != nil && right != nil {
				assignments = append(assignments, flowAssignment{
					targets: identifier.FindAllString(left.Utf8Text(source), -1),
					value:   right.Utf8Text(source), line: int(node.StartPosition().Row) + 1,
				})
			}
		case "call", "call_expression":
			calls = append(calls, flowCall{text: node.Utf8Text(source), line: int(node.StartPosition().Row) + 1})
		}
	})
	return assignments, calls
}

func analyzeFlow(file skil.File, assignments []flowAssignment, calls []flowCall) []skil.Finding {
	tainted := map[string]string{}
	// Iterate to a fixed point so ordering, aliases, and short assignment
	// chains do not hide a flow. The bound prevents hostile inputs from
	// creating unbounded analysis work.
	for pass := 0; pass <= len(assignments); pass++ {
		changed := false
		for _, assignment := range assignments {
			if sanitizers.MatchString(assignment.value) || normalizedPathExpression(assignment.value) {
				continue
			}
			origin := taintSources.FindString(assignment.value)
			if origin == "" {
				for _, dependency := range identifier.FindAllString(assignment.value, -1) {
					if tainted[dependency] != "" {
						origin = tainted[dependency]
						break
					}
				}
			}
			if origin == "" {
				continue
			}
			for _, target := range assignment.targets {
				if tainted[target] == "" {
					tainted[target] = origin
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	var findings []skil.Finding
	seen := map[string]bool{}
	for _, call := range calls {
		for _, sink := range taintSinks {
			if !sink.re.MatchString(call.text) {
				continue
			}
			variable, source := "", ""
			for _, candidate := range identifier.FindAllString(call.text, -1) {
				if tainted[candidate] != "" {
					variable, source = candidate, tainted[candidate]
					break
				}
			}
			if source == "" && taintSources.MatchString(call.text) {
				variable, source = "<direct>", taintSources.FindString(call.text)
			}
			if source == "" {
				continue
			}
			if sink.name == "network" && authenticationOnlyFlow(call.text, source) {
				continue
			}
			key := sink.name + "\x00" + fmt.Sprint(call.line) + "\x00" + variable
			if seen[key] {
				continue
			}
			seen[key] = true
			rule := RulePattern{Rule: skil.Rule{
				ID:    "SKIL-TAINT-" + strings.ToUpper(strings.ReplaceAll(sink.name, " ", "-")),
				Title: "Tainted data reaches " + sink.name, Category: "data-flow",
				Severity: sink.severity, Description: "Data from " + source + " reaches " + sink.name + ".",
				Analysis: "taint", Remediation: "Validate, constrain, and sanitize data before the sink.",
			}, Confidence: .9}
			finding := makeFinding(rule, file, call.line, call.text)
			finding.Evidence["source"] = source
			finding.Evidence["variable"] = variable
			finding.Evidence["sink"] = sink.name
			finding.Evidence["capability"] = sink.capability
			finding.Evidence["engine"] = "syntax-flow"
			findings = append(findings, finding)
		}
	}
	return findings
}

func normalizedPathExpression(value string) bool {
	compact := strings.ReplaceAll(value, " ", "")
	return strings.Contains(compact, "Path(") && strings.Contains(compact, ").name")
}

func authenticationOnlyFlow(call, source string) bool {
	lower := strings.ToLower(call)
	lowerSource := strings.ToLower(source)
	if !strings.Contains(lowerSource, "environ") && !strings.Contains(lowerSource, "getenv") &&
		!strings.Contains(lowerSource, "process.env") {
		return false
	}
	if !strings.Contains(lower, "authorization") ||
		(!strings.Contains(lower, "requests.get") && !strings.Contains(lower, "http.get")) {
		return false
	}
	for _, payload := range []string{"data=", "json=", "body=", "content="} {
		if strings.Contains(lower, payload) {
			return false
		}
	}
	return true
}
