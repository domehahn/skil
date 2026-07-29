package analyzer

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"

	"github.com/domehahn/skil/pkg/skil"
)

// PythonAST analyzes a real Python syntax tree. It never imports or executes
// the scanned module.
type PythonAST struct{}

func NewPythonAST() *PythonAST { return &PythonAST{} }

func (p *PythonAST) Rules() []skil.Rule {
	return []skil.Rule{{
		ID: "SKIL-PY-REFLECT-EXEC", Title: "Reflective Python execution", Category: "dynamic-execution",
		Severity: skil.SeverityHigh, Analysis: "ast", AppliesTo: []string{"py"},
		Description: "Python reflectively resolves and invokes an execution sink.",
		Remediation: "Use an explicit, reviewable function call and remove reflective execution.",
	}}
}

func (p *PythonAST) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.python-ast", Version: "1.0.0",
		Categories:    []string{"dynamic-execution", "data-boundary"},
		AnalysisTypes: []string{"ast"}, SupportedTypes: []string{"py"},
	}
}

type astRule struct {
	id, title, category, description, remediation, capability string
	severity                                                  skil.Severity
	confidence                                                float64
}

var pythonCalls = map[string]astRule{
	"exec":       pyRule("SKIL-PY-001", "Dynamic Python execution", "dangerous-code", "Python executes dynamic content with exec.", "Replace dynamic execution with a constrained parser.", "commands.execute", skil.SeverityHigh),
	"eval":       pyRule("SKIL-PY-001", "Dynamic Python execution", "dangerous-code", "Python evaluates dynamic content.", "Replace eval with a constrained parser.", "commands.execute", skil.SeverityHigh),
	"compile":    pyRule("SKIL-PY-001", "Dynamic Python execution", "dangerous-code", "Python compiles dynamic source.", "Avoid compiling untrusted content.", "commands.execute", skil.SeverityHigh),
	"__import__": pyRule("SKIL-PY-001", "Dynamic Python import", "dangerous-code", "Python dynamically resolves an import.", "Use explicit imports and allowlists.", "commands.execute", skil.SeverityHigh),

	"subprocess.run":          pyRule("SKIL-PY-002", "Python process execution", "dangerous-code", "Python starts an operating-system process.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"subprocess.call":         pyRule("SKIL-PY-002", "Python process execution", "dangerous-code", "Python starts an operating-system process.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"subprocess.Popen":        pyRule("SKIL-PY-002", "Python process execution", "dangerous-code", "Python starts an operating-system process.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"subprocess.check_output": pyRule("SKIL-PY-002", "Python process execution", "dangerous-code", "Python starts an operating-system process.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"subprocess.check_call":   pyRule("SKIL-PY-002", "Python process execution", "dangerous-code", "Python starts an operating-system process.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"os.system":               pyRule("SKIL-PY-002", "Python process execution", "dangerous-code", "Python invokes a shell command.", "Avoid shell invocation and use explicit arguments.", "commands.execute", skil.SeverityHigh),
	"pty.spawn":               pyRule("SKIL-PY-002", "PTY process execution", "dangerous-code", "Python spawns a pseudo-terminal process.", "Remove interactive process spawning.", "commands.execute", skil.SeverityHigh),

	"pickle.load":   pyRule("SKIL-PY-003", "Unsafe Python deserialization", "dangerous-code", "Pickle may execute behavior while deserializing.", "Use a non-executable data format.", "", skil.SeverityHigh),
	"pickle.loads":  pyRule("SKIL-PY-003", "Unsafe Python deserialization", "dangerous-code", "Pickle may execute behavior while deserializing.", "Use a non-executable data format.", "", skil.SeverityHigh),
	"marshal.load":  pyRule("SKIL-PY-003", "Unsafe Python deserialization", "dangerous-code", "Marshal is unsafe for untrusted input.", "Use a validated portable data format.", "", skil.SeverityHigh),
	"marshal.loads": pyRule("SKIL-PY-003", "Unsafe Python deserialization", "dangerous-code", "Marshal is unsafe for untrusted input.", "Use a validated portable data format.", "", skil.SeverityHigh),

	"requests.get":           pyRule("SKIL-NET-001", "Outbound network operation", "tool-misuse", "Python performs an outbound network request.", "Declare and constrain outbound network access.", "network.outbound", skil.SeverityMedium),
	"requests.post":          pyRule("SKIL-NET-001", "Outbound network operation", "tool-misuse", "Python performs an outbound network request.", "Declare and constrain outbound network access.", "network.outbound", skil.SeverityMedium),
	"requests.put":           pyRule("SKIL-NET-001", "Outbound network operation", "tool-misuse", "Python performs an outbound network request.", "Declare and constrain outbound network access.", "network.outbound", skil.SeverityMedium),
	"requests.delete":        pyRule("SKIL-NET-001", "Outbound network operation", "tool-misuse", "Python performs an outbound network request.", "Declare and constrain outbound network access.", "network.outbound", skil.SeverityMedium),
	"os.getenv":              pyRule("SKIL-SEC-001", "Environment or secret read", "data-exfiltration", "Python reads an environment variable that may contain secrets.", "Declare exact variables and avoid broad secret access.", "secrets.read", skil.SeverityHigh),
	"os.environ.get":         pyRule("SKIL-SEC-001", "Environment or secret read", "data-exfiltration", "Python reads an environment variable that may contain secrets.", "Declare exact variables and avoid broad secret access.", "secrets.read", skil.SeverityHigh),
	"urllib.request.urlopen": pyRule("SKIL-NET-001", "Outbound network operation", "tool-misuse", "Python performs an outbound network request.", "Declare and constrain outbound network access.", "network.outbound", skil.SeverityMedium),
}

func pyRule(id, title, category, description, remediation, capability string, severity skil.Severity) astRule {
	switch category {
	case "dangerous-code":
		category = "dynamic-execution"
	case "tool-misuse", "data-exfiltration":
		category = "data-boundary"
	}
	return astRule{id, title, category, description, remediation, capability, severity, .99}
}

func (p *PythonAST) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if extension(file.Path) != "py" {
			continue
		}
		tree, err := parsePython(ctx, file.Data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		aliases := collectAliases(tree.RootNode(), file.Data)
		reflectiveVars := collectReflectiveAliases(tree.RootNode(), file.Data, aliases)
		emit := func(node *tree_sitter.Node, target string, rule astRule) {
			rp := RulePattern{Rule: skil.Rule{ID: rule.id, Title: rule.title, Category: rule.category,
				Severity: rule.severity, Description: rule.description, Analysis: "ast", AppliesTo: []string{"py"},
				Remediation: rule.remediation}, Confidence: rule.confidence}
			start, end := node.StartPosition(), node.EndPosition()
			finding := makeFinding(rp, file, int(start.Row)+1, node.Utf8Text(file.Data))
			finding.Location.EndLine = int(end.Row) + 1
			finding.Evidence["call_target"] = target
			finding.Evidence["node_type"] = node.Kind()
			if rule.capability != "" {
				finding.Evidence["capability"] = rule.capability
			}
			literal := firstStringLiteral(node, file.Data)
			switch rule.capability {
			case "network.outbound":
				if parsed, err := url.Parse(literal); err == nil && parsed.Hostname() != "" {
					finding.Evidence["network_host"] = parsed.Hostname()
				}
			case "commands.execute":
				if literal != "" {
					finding.Evidence["command"] = strings.Fields(literal)[0]
				}
			case "filesystem.write":
				if literal != "" {
					finding.Evidence["filesystem_path"] = literal
				}
			case "secrets.read":
				if literal != "" {
					finding.Evidence["secret"] = literal
					finding.Evidence["environment"] = literal
				}
			}
			out = append(out, finding)
		}
		walkNode(tree.RootNode(), func(node *tree_sitter.Node) {
			if node.Kind() == "subscript" {
				text := resolvePythonTarget(node.Utf8Text(file.Data), aliases)
				if strings.HasPrefix(text, "os.environ[") {
					emit(node, "os.environ", pyRule("SKIL-SEC-001", "Environment or secret read", "data-exfiltration", "Python reads an environment variable that may contain secrets.", "Declare exact variables and avoid broad secret access.", "secrets.read", skil.SeverityHigh))
				}
				return
			}
			if node.Kind() != "call" {
				return
			}
			function := node.ChildByFieldName("function")
			if function == nil {
				return
			}
			if sink, ok := reflectiveGetattrSink(function, file.Data, aliases); ok {
				emit(node, sink.target, pyRule("SKIL-PY-REFLECT-EXEC", "Reflective Python execution", "dynamic-execution", "Python reflectively resolves and invokes an execution sink.", "Use an explicit, reviewable function call and remove reflective execution.", "commands.execute", skil.SeverityHigh))
				if underlying, ok := reflectiveUnderlyingRule(sink); ok {
					emit(node, sink.target, underlying)
				}
				return
			}
			if function.Kind() == "identifier" {
				if sink, ok := reflectiveVars[function.Utf8Text(file.Data)]; ok {
					emit(node, sink.target, pyRule("SKIL-PY-REFLECT-EXEC", "Reflective Python execution", "dynamic-execution", "Python reflectively resolves and invokes an execution sink.", "Use an explicit, reviewable function call and remove reflective execution.", "commands.execute", skil.SeverityHigh))
					if underlying, ok := reflectiveUnderlyingRule(sink); ok {
						emit(node, sink.target, underlying)
					}
					return
				}
			}
			target := resolvePythonTarget(function.Utf8Text(file.Data), aliases)
			rule, found := pythonCalls[target]
			if !found && strings.HasPrefix(target, "os.exec") {
				rule, found = pythonCalls["os.system"]
			}
			if target == "getattr" && dynamicGetattr(node) {
				rule, found = pyRule("SKIL-PY-004", "Dynamic attribute access", "dangerous-code", "Dynamic attribute selection can bypass allowlists.", "Validate the attribute against an explicit allowlist.", "", skil.SeverityMedium), true
			}
			if target == "open" && writeMode(node, file.Data) {
				rule, found = pyRule("SKIL-FS-001", "Filesystem write", "tool-misuse", "Python opens a file in a write-capable mode.", "Declare and constrain writable paths.", "filesystem.write", skil.SeverityMedium), true
			}
			if found && strings.HasPrefix(target, "subprocess.") && safeSubprocessCall(node, file.Data) {
				return
			}
			if !found {
				return
			}
			emit(node, target, rule)
		})
		tree.Close()
	}
	return out, nil
}

func safeSubprocessCall(call *tree_sitter.Node, source []byte) bool {
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return false
	}
	first := args.NamedChild(0)
	if first == nil || (first.Kind() != "list" && first.Kind() != "tuple") {
		return false
	}
	for i := uint(0); i < first.NamedChildCount(); i++ {
		child := first.NamedChild(i)
		if child == nil || child.Kind() != "string" {
			return false
		}
	}
	text := strings.ToLower(args.Utf8Text(source))
	return !strings.Contains(text, "shell=true")
}

func firstStringLiteral(node *tree_sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}
	if node.Kind() == "string" {
		return strings.Trim(node.Utf8Text(source), `"'`)
	}
	for i := uint(0); i < node.NamedChildCount(); i++ {
		if value := firstStringLiteral(node.NamedChild(i), source); value != "" {
			return value
		}
	}
	return ""
}

func parsePython(ctx context.Context, source []byte) (*tree_sitter.Tree, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(tree_sitter_python.Language())); err != nil {
		return nil, fmt.Errorf("configure parser: %w", err)
	}
	tree := parser.ParseWithOptions(func(offset int, _ tree_sitter.Point) []byte {
		if offset >= len(source) || ctx.Err() != nil {
			return nil
		}
		return source[offset:]
	}, nil, &tree_sitter.ParseOptions{ProgressCallback: func(_ tree_sitter.ParseState) bool {
		return ctx.Err() != nil
	}})
	if tree == nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("parser returned no syntax tree")
	}
	return tree, nil
}

func walkNode(node *tree_sitter.Node, visit func(*tree_sitter.Node)) {
	visit(node)
	for i := uint(0); i < node.NamedChildCount(); i++ {
		if child := node.NamedChild(i); child != nil {
			walkNode(child, visit)
		}
	}
}

func collectAliases(root *tree_sitter.Node, source []byte) map[string]string {
	aliases := map[string]string{}
	walkNode(root, func(node *tree_sitter.Node) {
		switch node.Kind() {
		case "import_statement":
			for i := uint(0); i < node.NamedChildCount(); i++ {
				name, local := importName(node.NamedChild(i), source)
				if name != "" {
					if local == "" {
						local = strings.Split(name, ".")[0]
					}
					aliases[local] = name
				}
			}
		case "import_from_statement":
			module := node.ChildByFieldName("module_name")
			if module == nil {
				return
			}
			moduleName := module.Utf8Text(source)
			for i := uint(0); i < node.NamedChildCount(); i++ {
				if node.FieldNameForNamedChild(uint32(i)) != "name" {
					continue
				}
				name, local := importName(node.NamedChild(i), source)
				if name != "" {
					if local == "" {
						local = name
					}
					aliases[local] = moduleName + "." + name
				}
			}
		}
	})
	return aliases
}

func importName(node *tree_sitter.Node, source []byte) (name, local string) {
	if node == nil {
		return "", ""
	}
	if node.Kind() == "aliased_import" {
		nameNode, aliasNode := node.ChildByFieldName("name"), node.ChildByFieldName("alias")
		if nameNode == nil || aliasNode == nil {
			return "", ""
		}
		return nameNode.Utf8Text(source), aliasNode.Utf8Text(source)
	}
	return node.Utf8Text(source), ""
}

func resolvePythonTarget(target string, aliases map[string]string) string {
	target = strings.TrimSpace(target)
	parts := strings.Split(target, ".")
	if resolved, ok := aliases[parts[0]]; ok {
		parts[0] = resolved
	}
	resolved := strings.Join(parts, ".")
	if strings.HasPrefix(resolved, "builtins.") {
		return strings.TrimPrefix(resolved, "builtins.")
	}
	return resolved
}

func dynamicGetattr(call *tree_sitter.Node) bool {
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() < 2 {
		return false
	}
	name := args.NamedChild(1)
	return name != nil && name.Kind() != "string"
}

// reflectiveSink is a resolved `getattr(module, "name")` reference to a
// dangerous sink, retaining the module/name so callers can also compose the
// equivalent direct-call rule (e.g. builtins.exec resolves to the same
// SKIL-PY-001 finding a literal `exec(...)` call would produce).
type reflectiveSink struct {
	target, module, name string
}

// collectReflectiveAliases finds simple assignments of the form
// `name = getattr(module, "attr")` where the resolved target is a dangerous
// execution sink, so a later call through the local variable (`name(...)`)
// is still recognized as reflective execution even though the getattr call
// and its invocation are separated. This extends the same alias-resolution
// layer used for import aliases to value aliases of a reflective sink.
func collectReflectiveAliases(root *tree_sitter.Node, source []byte, aliases map[string]string) map[string]reflectiveSink {
	reflective := map[string]reflectiveSink{}
	walkNode(root, func(node *tree_sitter.Node) {
		if node.Kind() != "assignment" {
			return
		}
		left := node.ChildByFieldName("left")
		right := node.ChildByFieldName("right")
		if left == nil || right == nil || left.Kind() != "identifier" || right.Kind() != "call" {
			return
		}
		if sink, ok := reflectiveGetattrSink(right, source, aliases); ok {
			reflective[left.Utf8Text(source)] = sink
		}
	})
	return reflective
}

func reflectiveGetattrSink(function *tree_sitter.Node, source []byte, aliases map[string]string) (reflectiveSink, bool) {
	if function == nil || function.Kind() != "call" {
		return reflectiveSink{}, false
	}
	getter := function.ChildByFieldName("function")
	args := function.ChildByFieldName("arguments")
	if getter == nil || args == nil || resolvePythonTarget(getter.Utf8Text(source), aliases) != "getattr" || args.NamedChildCount() < 2 {
		return reflectiveSink{}, false
	}
	object, attribute := args.NamedChild(0), args.NamedChild(1)
	if object == nil || attribute == nil || attribute.Kind() != "string" {
		return reflectiveSink{}, false
	}
	module := resolvePythonTarget(object.Utf8Text(source), aliases)
	name := strings.Trim(attribute.Utf8Text(source), `"'`)
	dangerous := (module == "os" && (name == "system" || strings.HasPrefix(name, "exec"))) ||
		(module == "builtins" && (name == "exec" || name == "eval" || name == "compile"))
	if !dangerous {
		return reflectiveSink{}, false
	}
	return reflectiveSink{target: "getattr(" + module + ", " + name + ")", module: module, name: name}, true
}

// reflectiveUnderlyingRule maps a resolved reflective getattr(module, name)
// sink to the same rule a direct, non-reflective call would have produced
// (e.g. getattr(builtins, "exec") behaves like a literal exec(...) call).
// Composing this from the existing pythonCalls table keeps a reflective
// exec/eval/system call classified consistently with its direct form.
func reflectiveUnderlyingRule(sink reflectiveSink) (astRule, bool) {
	switch {
	case sink.module == "builtins" && (sink.name == "exec" || sink.name == "eval" || sink.name == "compile"):
		rule, ok := pythonCalls[sink.name]
		return rule, ok
	case sink.module == "os" && (sink.name == "system" || strings.HasPrefix(sink.name, "exec")):
		rule, ok := pythonCalls["os.system"]
		return rule, ok
	default:
		return astRule{}, false
	}
}

func writeMode(call *tree_sitter.Node, source []byte) bool {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return false
	}
	for i := uint(1); i < args.NamedChildCount(); i++ {
		text := strings.Trim(args.NamedChild(i).Utf8Text(source), `"' `)
		if strings.ContainsAny(text, "wax+") {
			return true
		}
	}
	return false
}
