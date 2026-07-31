package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"sort"
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
	taintSources = regexp.MustCompile(`(?i)(os\.environ|os\.getenv|process\.env|input\s*\(|sys\.stdin|request\.(?:args|query|body)|readFile|open\s*\([^)]*["']r|tool[_ .-]?output|mcp[_ .-]?output|model[_ .-]?output|llm[_ .-]?response|assistant[_ .-]?response|completion\s*=|\.(?:responses|chat|completions|generate)\.(?:create|complete)\s*\()`)
	sanitizers   = regexp.MustCompile(`(?i)\b(?:sanitize|validate|allowlist|whitelist|escape|urlparse|url\.parse|path\.resolve)\s*\(`)
	identifier   = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)

	privilegedContextVars = regexp.MustCompile(`(?i)^(?:system_prompt|developer_instructions?|hidden_context|privileged_context|system_prompt_text|developer_guidance|private_context|internal_prompt)$`)
	taintSinks            = []struct {
		name, capability string
		re               *regexp.Regexp
		severity         skil.Severity
	}{
		{"network", "network.outbound", regexp.MustCompile(`(?i)(requests\.(?:post|put|get)|fetch\s*\(|axios\.(?:post|get)|http\.(?:request|get)|urllib\.request)`), skil.SeverityCritical},
		{"execution", "commands.execute", regexp.MustCompile(`(?i)(exec\s*\(|eval\s*\(|subprocess\.|os\.system|child_process\.)`), skil.SeverityCritical},
		{"filesystem write", "filesystem.write", regexp.MustCompile(`(?i)(open\s*\([^)]*["'][wa+]|writeFile|\.write\s*\()`), skil.SeverityHigh},
		{"log", "external_side_effects", regexp.MustCompile(`(?i)(print\s*\(|console\.log|log(?:ger)?\.)`), skil.SeverityMedium},
		{"output-execution", "commands.execute", regexp.MustCompile(`(?i)(exec\s*\(|eval\s*\(|innerHTML|inner_html|dangerouslySetInnerHTML|v-html|\.html\(|\.append\(|shell\s*\(|subprocess\.)`), skil.SeverityCritical},
		{"output-sql", "commands.execute", regexp.MustCompile(`(?i)(execute\s*\(|cursor\.execute|db\.execute|query\s*\(|session\.execute)`), skil.SeverityCritical},
		{"output-agent", "multi-agent", regexp.MustCompile(`(?i)(agent\.send|a2a\.send|peer\.send|agent\.call|send_to_agent|forward_to|send_message)`), skil.SeverityHigh},
	}
)

type flowAssignment struct {
	targets []string
	value   string
	line    int
}

type flowCall struct {
	text, callee string
	arguments    []string
	line         int
}

type flowSummary struct {
	sources map[string]string
	sinks   map[string]map[int][]int
	defined map[string]bool
}

type fileFlow struct {
	file        skil.File
	assignments []flowAssignment
	calls       []flowCall
}

func NewTaint() *Taint { return &Taint{} }
func (t *Taint) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.taint", Version: "2.0.0",
		Domain: "code", Subdomain: "taint",
		Categories: []string{"data-flow"}, AnalysisTypes: []string{"taint"},
		SupportedTypes: []string{"py", "js", "jsx", "ts", "tsx"}}
}

func (t *Taint) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	summary := flowSummary{sources: map[string]string{}, sinks: map[string]map[int][]int{}, defined: map[string]bool{}}
	definitionCounts := map[string]int{}
	var files []fileFlow
	for _, file := range ac.Artifact.Files {
		language := taintLanguage(extension(file.Path))
		if language == nil {
			continue
		}
		tree, err := parseStructured(ctx, file.Data, language)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		assignments, calls, localSummary := collectFlowNodes(tree.RootNode(), file.Data)
		if extension(file.Path) == "py" {
			// Reuse the same Python import-alias resolution the AST analyzer
			// uses (collectAliases in python_ast.go) so `import x as y; y.f()`
			// is recognized as `x.f()` for taint source/sink matching too,
			// instead of re-implementing a second, weaker alias layer here.
			aliasPatterns := compilePythonAliasPatterns(collectAliases(tree.RootNode(), file.Data))
			for i := range calls {
				calls[i].text = resolvePythonAliasesInText(calls[i].text, aliasPatterns)
			}
			for i := range assignments {
				assignments[i].value = resolvePythonAliasesInText(assignments[i].value, aliasPatterns)
			}
		}
		tree.Close()
		for name, source := range localSummary.sources {
			if summary.sources[name] == "" {
				summary.sources[name] = source
			}
		}
		for name, sinks := range localSummary.sinks {
			if summary.sinks[name] == nil {
				summary.sinks[name] = map[int][]int{}
			}
			for sink, parameters := range sinks {
				summary.sinks[name][sink] = append(summary.sinks[name][sink], parameters...)
			}
		}
		for name := range localSummary.defined {
			definitionCounts[name]++
		}
		files = append(files, fileFlow{file: file, assignments: assignments, calls: calls})
	}
	for name, count := range definitionCounts {
		if count > 1 {
			delete(summary.sources, name)
			delete(summary.sinks, name)
		}
	}
	var out []skil.Finding
	for _, file := range files {
		out = append(out, analyzeFlow(file.file, file.assignments, file.calls, summary)...)
	}
	return out, nil
}

// pythonAliasPattern pairs a precompiled alias-reference pattern with the
// canonical module name it resolves to.
type pythonAliasPattern struct {
	pattern   *regexp.Regexp
	canonical string
}

// compilePythonAliasPatterns compiles each import alias's reference pattern
// once per file, so resolvePythonAliasesInText (called once per call and
// once per assignment) never recompiles a regular expression per
// substitution.
func compilePythonAliasPatterns(aliases map[string]string) []pythonAliasPattern {
	if len(aliases) == 0 {
		return nil
	}
	patterns := make([]pythonAliasPattern, 0, len(aliases))
	for local, canonical := range aliases {
		if local == "" || local == canonical {
			continue
		}
		patterns = append(patterns, pythonAliasPattern{
			pattern:   regexp.MustCompile(`\b` + regexp.QuoteMeta(local) + `\.`),
			canonical: canonical,
		})
	}
	return patterns
}

// resolvePythonAliasesInText rewrites occurrences of an imported local alias
// (e.g. "rq" from `import requests as rq`) to its canonical dotted module
// name (e.g. "requests") within a snippet of source text, using patterns
// already compiled once for the whole file, so downstream regex-based
// source/sink matching sees the real module regardless of the alias used at
// the call site.
func resolvePythonAliasesInText(text string, aliasPatterns []pythonAliasPattern) string {
	for _, alias := range aliasPatterns {
		text = alias.pattern.ReplaceAllString(text, alias.canonical+".")
	}
	return text
}

// untrustedOutputOrigin reports whether a taint source describes external or
// generated input (stdin, HTTP request data, file reads, or upstream
// tool/model output) rather than a purely local value. It is used to derive
// an "untrusted output reaches execution" finding from existing taint and
// AST evidence instead of re-detecting the same condition with a separate
// text pattern.
var untrustedOutputOrigin = regexp.MustCompile(`(?i)input\s*\(|stdin|request\.(?:args|query|body)|readfile|tool[_ .-]?output|mcp[_ .-]?output|model[_ .-]?output|llm[_ .-]?response|assistant[_ .-]?response|completion\s*=|\.(?:responses|chat|completions|generate)\.(?:create|complete)\s*\(`)

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

func collectFlowNodes(root *tree_sitter.Node, source []byte) ([]flowAssignment, []flowCall, flowSummary) {
	var assignments []flowAssignment
	var calls []flowCall
	summary := flowSummary{sources: map[string]string{}, sinks: map[string]map[int][]int{}, defined: map[string]bool{}}
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
			calls = append(calls, describeFlowCall(node, source))
		case "function_definition", "function_declaration", "method_definition":
			nameNode := node.ChildByFieldName("name")
			if nameNode == nil {
				return
			}
			name := nameNode.Utf8Text(source)
			summary.defined[name] = true
			origin, sinks := summarizeFunction(node, source)
			if origin != "" {
				summary.sources[name] = origin
			}
			if len(sinks) > 0 {
				summary.sinks[name] = sinks
			}
		}
	})
	return assignments, calls, summary
}

func describeFlowCall(node *tree_sitter.Node, source []byte) flowCall {
	call := flowCall{text: node.Utf8Text(source), line: int(node.StartPosition().Row) + 1}
	function := node.ChildByFieldName("function")
	if function == nil {
		function = node.ChildByFieldName("callee")
	}
	if function != nil {
		names := identifier.FindAllString(function.Utf8Text(source), -1)
		if len(names) > 0 {
			call.callee = names[len(names)-1]
		}
	}
	if arguments := node.ChildByFieldName("arguments"); arguments != nil {
		for index := uint(0); index < arguments.NamedChildCount(); index++ {
			call.arguments = append(call.arguments, arguments.NamedChild(index).Utf8Text(source))
		}
	}
	return call
}

func summarizeFunction(node *tree_sitter.Node, source []byte) (string, map[int][]int) {
	parameters := map[string]int{}
	if parameterNode := node.ChildByFieldName("parameters"); parameterNode != nil {
		for index := uint(0); index < parameterNode.NamedChildCount(); index++ {
			if name := simpleParameterName(parameterNode.NamedChild(index), source); name != "" {
				parameters[name] = int(index)
			}
		}
	}
	origin := ""
	sinkParameters := map[int]map[int]bool{}
	walkNode(node, func(child *tree_sitter.Node) {
		switch child.Kind() {
		case "return_statement":
			if candidate := taintSources.FindString(child.Utf8Text(source)); candidate != "" {
				origin = candidate
			}
		case "call", "call_expression":
			call := describeFlowCall(child, source)
			for index, sink := range taintSinks {
				if !sink.re.MatchString(call.text) {
					continue
				}
				for _, argument := range call.arguments {
					for _, name := range identifier.FindAllString(argument, -1) {
						position, exists := parameters[name]
						if !exists {
							continue
						}
						if sinkParameters[index] == nil {
							sinkParameters[index] = map[int]bool{}
						}
						sinkParameters[index][position] = true
					}
				}
			}
		}
	})
	sinks := make(map[int][]int, len(sinkParameters))
	for sink, positions := range sinkParameters {
		for position := range positions {
			sinks[sink] = append(sinks[sink], position)
		}
		sort.Ints(sinks[sink])
	}
	return origin, sinks
}

func simpleParameterName(node *tree_sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}
	if node.Kind() == "identifier" {
		return node.Utf8Text(source)
	}
	for _, field := range []string{"name", "pattern"} {
		if candidate := node.ChildByFieldName(field); candidate != nil && candidate.Kind() == "identifier" {
			return candidate.Utf8Text(source)
		}
	}
	names := identifier.FindAllString(node.Utf8Text(source), -1)
	if len(names) == 1 {
		return names[0]
	}
	return ""
}

func analyzeFlow(file skil.File, assignments []flowAssignment, calls []flowCall, summary flowSummary) []skil.Finding {
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
			summarySource := false
			if origin == "" {
				for _, function := range sortedSummaryNames(summary.sources) {
					source := summary.sources[function]
					if regexp.MustCompile(`\b` + regexp.QuoteMeta(function) + `\s*\(`).MatchString(assignment.value) {
						origin = source
						summarySource = true
						break
					}
				}
			}
			if origin == "" {
				for _, dependency := range identifier.FindAllString(assignment.value, -1) {
					if tainted[dependency] != "" {
						origin = tainted[dependency]
						break
					}
				}
			}
			for _, target := range assignment.targets {
				if privilegedContextVars.MatchString(target) {
					origin = "privileged_context"
					break
				}
			}
			if origin == "" {
				continue
			}
			for _, target := range assignment.targets {
				if tainted[target] == "" {
					tainted[target] = origin
					changed = true
					if summarySource {
						tainted[target] = "function-summary:" + origin
					}
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
		for sinkIndex, sink := range taintSinks {
			directSink := sink.re.MatchString(call.text)
			summarySink := false
			searchText := call.text
			if !directSink {
				for _, function := range sortedSinkSummaryNames(summary.sinks) {
					positions := summary.sinks[function][sinkIndex]
					if len(positions) == 0 || call.callee != function {
						continue
					}
					var selected []string
					for _, position := range positions {
						if position >= 0 && position < len(call.arguments) {
							selected = append(selected, call.arguments[position])
						}
					}
					if len(selected) == 0 {
						continue
					}
					summarySink = true
					searchText = strings.Join(selected, "\n")
					break
				}
			}
			if !directSink && !summarySink {
				continue
			}
			variable, source := "", ""
			for _, candidate := range identifier.FindAllString(searchText, -1) {
				if tainted[candidate] != "" {
					variable, source = candidate, tainted[candidate]
					break
				}
			}
			if source == "" && taintSources.MatchString(searchText) {
				variable, source = "<direct>", taintSources.FindString(searchText)
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
			if summarySink || strings.HasPrefix(source, "function-summary:") {
				finding.Evidence["engine"] = "whole-artifact-function-summary"
			}
			findings = append(findings, finding)
			// Compose a higher-level "untrusted output reached execution"
			// finding from this same taint evidence when the source looks
			// like external or generated input, rather than re-detecting the
			// condition with a separate text-matching rule.
			if sink.name == "execution" && untrustedOutputOrigin.MatchString(source) {
				outputRule := RulePattern{Rule: skil.Rule{
					ID: "SKIL-OUTPUT-EXECUTION", Title: "Unvalidated generated-output execution",
					Category: "output-trust", Severity: skil.SeverityHigh,
					Description: "Data from external input or generated output reaches a dynamic execution sink.",
					Analysis:    "taint", Remediation: "Validate and encode output before use; do not execute it directly.",
				}, Confidence: .92}
				outputFinding := makeFinding(outputRule, file, call.line, call.text)
				outputFinding.Evidence["source"] = source
				outputFinding.Evidence["variable"] = variable
				outputFinding.Evidence["sink"] = sink.name
				outputFinding.Evidence["capability"] = "commands.execute"
				outputFinding.Evidence["engine"] = "taint-composition"
				findings = append(findings, outputFinding)
			}
			if source == "privileged_context" {
				privRule := RulePattern{Rule: skil.Rule{
					ID: "SKIL-TAINT-PRIVILEGED-CONTEXT", Title: "Privileged context reaches external sink",
					Category: "data-flow", Severity: skil.SeverityCritical,
					Description: "Privileged context (system prompt, developer instructions, or hidden instructions) flows to an external sink.",
					Analysis:    "taint", Remediation: "Constrain privileged context to local processing only.",
				}, Confidence: .95}
				privFinding := makeFinding(privRule, file, call.line, call.text)
				privFinding.Evidence["source"] = source
				privFinding.Evidence["variable"] = variable
				privFinding.Evidence["sink"] = sink.name
				privFinding.Evidence["capability"] = sink.capability
				privFinding.Evidence["engine"] = "syntax-flow"
				findings = append(findings, privFinding)
			}
		}
	}
	return findings
}

func sortedSummaryNames(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedSinkSummaryNames(values map[string]map[int][]int) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
