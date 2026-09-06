package analyzer

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
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
		Domain: "code", Subdomain: "ast",
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
	findings, _, err := p.AnalyzeCapabilities(ctx, ac)
	return findings, err
}

// AnalyzeCapabilities performs the same syntax-tree walk as Analyze but also
// records a CapabilityObservation for every capability-relevant call it
// resolves, whether or not that call was unsafe enough to also produce a
// Finding. This keeps "the skill uses this capability" (observation)
// independent of "this specific use is dangerous" (finding): a safe,
// argv-only subprocess call is legitimate declared-capability usage and
// must be observable even though it deliberately produces no Finding.
func (p *PythonAST) AnalyzeCapabilities(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, []skil.CapabilityObservation, error) {
	var out []skil.Finding
	var observations []skil.CapabilityObservation
	for _, file := range ac.Artifact.Files {
		if extension(file.Path) != "py" {
			continue
		}
		tree, err := parsePython(ctx, file.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		aliases := collectAliases(tree.RootNode(), file.Data)
		reflectiveVars := collectReflectiveAliases(tree.RootNode(), file.Data, aliases)
		facts := collectPythonValueFacts(tree.RootNode(), file.Data, aliases)
		observe := func(node *tree_sitter.Node, target, capability, value string, evidence map[string]any) {
			if capability == "" {
				return
			}
			start := node.StartPosition()
			obs := skil.CapabilityObservation{
				Capability: capability, Value: value, Analyzer: "builtin.python-ast",
				Location: skil.Location{File: file.Path, StartLine: int(start.Row) + 1, EndLine: int(start.Row) + 1},
				Evidence: map[string]any{"call_target": target},
			}
			for k, v := range evidence {
				obs.Evidence[k] = v
			}
			observations = append(observations, obs)
		}
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
			value := ""
			switch rule.capability {
			case "network.outbound":
				if parsed, err := url.Parse(literal); err == nil && parsed.Hostname() != "" {
					finding.Evidence["network_host"] = parsed.Hostname()
					value = parsed.Hostname()
				}
			case "commands.execute":
				if literal != "" {
					value = strings.Fields(literal)[0]
					finding.Evidence["command"] = value
				}
			case "filesystem.write":
				if literal != "" {
					finding.Evidence["filesystem_path"] = literal
					value = literal
				}
			case "secrets.read":
				if literal != "" {
					finding.Evidence["secret"] = literal
					finding.Evidence["environment"] = literal
					value = literal
				}
			}
			out = append(out, finding)
			observe(node, target, rule.capability, value, finding.Evidence)
			if rule.capability == "secrets.read" && value != "" {
				// An environment-variable read is simultaneously a
				// secrets.read concern (the value may hold a secret) and a
				// distinct declared environment.read capability in the
				// skill contract schema; both must be independently
				// observable so contract verification can tie either
				// declaration to real usage.
				observe(node, target, "environment.read", value, finding.Evidence)
			}
		}
		walkNode(tree.RootNode(), func(node *tree_sitter.Node) {
			if node.Kind() == "subscript" {
				text := resolvePythonTarget(node.Utf8Text(file.Data), aliases)
				if strings.HasPrefix(text, "os.environ[") {
					rule := pyRule("SKIL-SEC-001", "Environment or secret read", "data-exfiltration", "Python reads an environment variable that may contain secrets.", "Declare exact variables and avoid broad secret access.", "secrets.read", skil.SeverityHigh)
					if secretUsedOnlyForAuthentication(assignedVariableName(node, file.Data), file.Data) {
						// The value is used exclusively as an Authorization
						// header on a single fixed-destination GET call, with
						// no other use anywhere in the file — the shape every
						// legitimate authenticated API client has. This is
						// still genuinely observed secrets.read capability
						// usage and must remain observable, but it must not
						// produce a Finding; see safeSubprocessCall below for
						// the same "safe declared use is observe-only" pattern.
						observe(node, "os.environ", "secrets.read", "", map[string]any{"node_type": node.Kind(), "authentication_only": true})
						return
					}
					emit(node, "os.environ", rule)
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
			if sink, ok := reflectiveVarsSubscriptSink(function, file.Data, aliases); ok {
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
			if target == "open" {
				if args := node.ChildByFieldName("arguments"); args != nil && args.NamedChildCount() > 0 {
					if constructed, ok := resolveConstructedPath(args.NamedChild(0), file.Data, aliases, facts, 0); ok {
						if sensitive, matched := sensitiveConstructedPath(constructed); sensitive {
							finding := makeFinding(RulePattern{Rule: skil.Rule{
								ID: "SKIL-SEC-001", Title: "Constructed sensitive file access", Category: "data-boundary",
								Severity: skil.SeverityHigh, Analysis: "ast", AppliesTo: []string{"py"},
								Description: "Python statically constructs a path to a well-known sensitive credential/config location (via chained pathlib '/' joins or os.path.join), rather than opening a literal string path — invisible to detection that only recognizes a sensitive path as a literal string.",
								Remediation: "Avoid programmatic access to well-known credential stores; if legitimate, declare the exact capability explicitly.",
							}, Confidence: .9}, file, int(node.StartPosition().Row)+1, node.Utf8Text(file.Data))
							finding.Evidence["call_target"] = target
							finding.Evidence["node_type"] = node.Kind()
							finding.Evidence["constructed_path"] = constructed
							finding.Evidence["matched_sensitive_root"] = matched
							finding.Evidence["capability"] = "secrets.read"
							out = append(out, finding)
							observe(node, target, "secrets.read", constructed, map[string]any{"node_type": node.Kind(), "constructed_path": constructed})
							return
						}
					}
				}
			}
			if target == "open" && writeMode(node, file.Data) {
				rule, found = pyRule("SKIL-FS-001", "Filesystem write", "tool-misuse", "Python opens a file in a write-capable mode.", "Declare and constrain writable paths.", "filesystem.write", skil.SeverityMedium), true
			}
			if target == "open" && !found && !writeMode(node, file.Data) {
				// A file opened in (the default) read mode is not itself
				// dangerous and must not produce a Finding, but it is
				// legitimate declared filesystem.read capability usage and
				// must still be observable, mirroring the safe-subprocess
				// observation below.
				literal := firstStringLiteral(node, file.Data)
				observe(node, target, "filesystem.read", literal, map[string]any{"node_type": node.Kind()})
				return
			}
			if found && strings.HasPrefix(target, "subprocess.") {
				safe, unresolved := safeSubprocessCall(node, file.Data, facts)
				if safe {
					// A safe, argv-only subprocess call is legitimate declared
					// capability usage: it must not produce a Finding, but the
					// capability was genuinely observed and must be recorded as
					// such, or verification cannot distinguish "safely used a
					// declared capability" from "never used it at all".
					literal := firstStringLiteral(node, file.Data)
					value := ""
					evidence := map[string]any{"node_type": node.Kind()}
					if literal != "" {
						value = strings.Fields(literal)[0]
						evidence["command"] = value
					}
					observe(node, target, "commands.execute", value, evidence)
					return
				}
				if unresolved {
					// The shell= value (or an unpacked **kwargs dict's "shell"
					// key) references something this bounded, literal-only
					// value-propagation pass cannot prove true or false (a
					// function call, an unresolved variable, a comprehension,
					// ...). Ambiguous must never be silently treated as safe:
					// this still reports, but the evidence says the flag
					// itself is unresolved rather than confirmed shell=True,
					// so a reviewer sees exactly what was and wasn't proven.
					emit(node, target, rule)
					out[len(out)-1].Evidence["shell_flag_resolution"] = "unresolved"
					return
				}
			}
			if !found {
				return
			}
			if rule.id == "SKIL-SEC-001" && secretUsedOnlyForAuthentication(assignedVariableName(node, file.Data), file.Data) {
				// See the identical guard on the os.environ[...] subscript
				// case above for the rationale.
				observe(node, target, "secrets.read", "", map[string]any{"node_type": node.Kind(), "authentication_only": true})
				return
			}
			emit(node, target, rule)
		})
		tree.Close()
	}
	return out, observations, nil
}

// safeSubprocessCall reports whether an argv-only subprocess call (its
// first positional argument a list/tuple of string literals) is safe to
// treat as ordinary declared commands.execute capability usage rather than
// a Finding. safe is true only when shell is absent or resolves to a
// literal False; unresolved is true when the shell= value (or an unpacked
// **kwargs dict's "shell" key) references something this bounded,
// literal-only value-propagation pass cannot prove — an unresolved
// identifier, a function call, a comprehension, or a **kwargs unpacking of
// something other than a tracked dict literal. Ambiguous is never treated
// as safe: callers must report it, distinguishing "confirmed shell=True"
// from "shell flag could not be proven either way" in evidence.
func safeSubprocessCall(call *tree_sitter.Node, source []byte, facts pythonValueFacts) (safe, unresolved bool) {
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return false, false
	}
	first := args.NamedChild(0)
	if first == nil || (first.Kind() != "list" && first.Kind() != "tuple") {
		return false, false
	}
	for i := uint(0); i < first.NamedChildCount(); i++ {
		child := first.NamedChild(i)
		if child == nil || child.Kind() != "string" {
			return false, false
		}
	}
	switch resolveShellFlag(args, source, facts) {
	case shellFlagResolvedTrue:
		return false, false
	case shellFlagUnresolved:
		return false, true
	default: // absent, or resolved False
		return true, false
	}
}

// pythonValueFacts holds bounded, single-pass, module-scope-level constant
// and dict-literal facts — the value-propagation slice of a Python
// semantic resolution layer. Deliberately last-assignment-wins and
// single-scope (matching collectAliases' own scope level), and limited to
// literal booleans and strings: this is constant propagation, never
// general dataflow, and it never claims to resolve anything beyond a
// direct literal assignment (no function calls, no conditionals, no
// cross-file resolution).
type pythonValueFacts struct {
	constants map[string]string            // identifier -> "true" | "false" | <string value>
	dicts     map[string]map[string]string // identifier -> {key -> "true" | "false" | <string value>}
	paths     map[string]string            // identifier -> reconstructed, normalized home-relative path (e.g. "~/.ssh/id_rsa")
}

func collectPythonValueFacts(root *tree_sitter.Node, source []byte, aliases map[string]string) pythonValueFacts {
	facts := pythonValueFacts{constants: map[string]string{}, dicts: map[string]map[string]string{}, paths: map[string]string{}}
	walkNode(root, func(node *tree_sitter.Node) {
		if node.Kind() != "assignment" {
			return
		}
		left := node.ChildByFieldName("left")
		right := node.ChildByFieldName("right")
		if left == nil || right == nil || left.Kind() != "identifier" {
			return
		}
		name := left.Utf8Text(source)
		switch right.Kind() {
		case "true", "false":
			facts.constants[name] = right.Kind()
		case "string":
			facts.constants[name] = strings.Trim(right.Utf8Text(source), `"'`)
		case "dictionary":
			entry := map[string]string{}
			for i := uint(0); i < right.NamedChildCount(); i++ {
				pair := right.NamedChild(i)
				if pair == nil || pair.Kind() != "pair" {
					continue
				}
				key, value := pair.ChildByFieldName("key"), pair.ChildByFieldName("value")
				if key == nil || value == nil || key.Kind() != "string" {
					continue
				}
				keyText := strings.Trim(key.Utf8Text(source), `"'`)
				switch value.Kind() {
				case "true", "false":
					entry[keyText] = value.Kind()
				case "string":
					entry[keyText] = strings.Trim(value.Utf8Text(source), `"'`)
				}
			}
			facts.dicts[name] = entry
		case "binary_operator", "call":
			// A straight-line, top-to-bottom pass: by the time this
			// assignment is visited, any earlier variable it references has
			// already been recorded into facts.paths, so
			// `ssh = home / ".ssh"; key = ssh / "id_rsa"` resolves key
			// correctly even though home/ssh are two separate prior
			// assignments. This is still bounded, single-scope, and
			// order-dependent (matching every other fact this pass tracks)
			// — not general dataflow.
			if resolved, ok := resolveConstructedPath(right, source, aliases, facts, 0); ok {
				facts.paths[name] = resolved
			}
		}
	})
	return facts
}

// resolveConstructedPath attempts a bounded, deterministic reconstruction
// of a Python path-construction expression into a normalized, forward-
// slash, home-relative path string (e.g. "~/.ssh/id_rsa"). It recognizes
// exactly two idioms: chained pathlib '/' joins rooted at Path.home() (or
// os.path.expanduser("~")), and os.path.join(...) calls whose arguments
// are themselves resolvable. Anything else — a non-'/' operator, an
// unresolved identifier, any other call — returns ok=false rather than
// guessing at a partial reconstruction.
func resolveConstructedPath(node *tree_sitter.Node, source []byte, aliases map[string]string, facts pythonValueFacts, depth int) (string, bool) {
	if node == nil || depth > 16 {
		return "", false
	}
	switch node.Kind() {
	case "string":
		return strings.Trim(node.Utf8Text(source), `"'`), true
	case "identifier":
		name := node.Utf8Text(source)
		if value, ok := facts.paths[name]; ok {
			return value, true
		}
		if value, ok := facts.constants[name]; ok {
			return value, true
		}
		return "", false
	case "binary_operator":
		op := node.ChildByFieldName("operator")
		if op == nil || op.Utf8Text(source) != "/" {
			return "", false
		}
		left, right := node.ChildByFieldName("left"), node.ChildByFieldName("right")
		if left == nil || right == nil {
			return "", false
		}
		leftPath, ok := resolveConstructedPath(left, source, aliases, facts, depth+1)
		if !ok {
			return "", false
		}
		rightPath, ok := resolveConstructedPath(right, source, aliases, facts, depth+1)
		if !ok {
			return "", false
		}
		return strings.TrimRight(leftPath, "/") + "/" + strings.TrimLeft(rightPath, "/"), true
	case "call":
		return resolveConstructedPathCall(node, source, aliases, facts, depth)
	default:
		return "", false
	}
}

func resolveConstructedPathCall(node *tree_sitter.Node, source []byte, aliases map[string]string, facts pythonValueFacts, depth int) (string, bool) {
	function := node.ChildByFieldName("function")
	args := node.ChildByFieldName("arguments")
	if function == nil {
		return "", false
	}
	target := resolvePythonTarget(function.Utf8Text(source), aliases)
	switch target {
	case "Path.home", "pathlib.Path.home":
		return "~", true
	case "os.path.expanduser":
		if args == nil || args.NamedChildCount() != 1 {
			return "", false
		}
		value, ok := resolveConstructedPath(args.NamedChild(0), source, aliases, facts, depth+1)
		if !ok || value != "~" {
			// Only the exact home-directory idiom (expanduser("~")) is
			// recognized; any other expanduser argument is declined, not
			// guessed at.
			return "", false
		}
		return "~", true
	case "os.path.join":
		if args == nil || args.NamedChildCount() == 0 {
			return "", false
		}
		segments := make([]string, 0, args.NamedChildCount())
		for i := uint(0); i < args.NamedChildCount(); i++ {
			segment, ok := resolveConstructedPath(args.NamedChild(i), source, aliases, facts, depth+1)
			if !ok {
				return "", false
			}
			segments = append(segments, strings.Trim(segment, "/"))
		}
		return strings.Join(segments, "/"), true
	default:
		return "", false
	}
}

// sensitiveConstructedPathPattern matches a normalized, home-relative
// constructed path (see resolveConstructedPath) against a curated set of
// well-known credential/config locations. Matching only ever depends on
// the reconstructed path itself, never a variable name.
var sensitiveConstructedPathPattern = regexp.MustCompile(
	`^~/(\.ssh(/|$)|\.aws(/|$)|\.config/gcloud(/|$)|\.kube(/|$)|\.docker(/|$)|\.npmrc$|\.pypirc$|\.git-credentials$)`)

func sensitiveConstructedPath(path string) (bool, string) {
	match := sensitiveConstructedPathPattern.FindString(path)
	return match != "", strings.TrimSuffix(match, "/")
}

type shellFlagResolution int

const (
	shellFlagAbsent shellFlagResolution = iota
	shellFlagResolvedFalse
	shellFlagResolvedTrue
	shellFlagUnresolved
)

// resolveShellFlag inspects a call's argument_list for a shell= keyword
// argument or an unpacked **kwargs dict's "shell" key, resolving it against
// facts (literal booleans and identifiers/dicts collectPythonValueFacts
// already tracked). Later arguments win over earlier ones, matching
// Python's own last-keyword/last-unpack-wins runtime semantics.
func resolveShellFlag(args *tree_sitter.Node, source []byte, facts pythonValueFacts) shellFlagResolution {
	resolveValue := func(value *tree_sitter.Node) shellFlagResolution {
		switch value.Kind() {
		case "true":
			return shellFlagResolvedTrue
		case "false":
			return shellFlagResolvedFalse
		case "identifier":
			switch facts.constants[value.Utf8Text(source)] {
			case "true":
				return shellFlagResolvedTrue
			case "false":
				return shellFlagResolvedFalse
			default:
				return shellFlagUnresolved
			}
		default:
			return shellFlagUnresolved
		}
	}
	result := shellFlagAbsent
	for i := uint(0); i < args.NamedChildCount(); i++ {
		child := args.NamedChild(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "keyword_argument":
			name := child.ChildByFieldName("name")
			if name == nil || name.Utf8Text(source) != "shell" {
				continue
			}
			value := child.ChildByFieldName("value")
			if value == nil {
				continue
			}
			result = resolveValue(value)
		case "dictionary_splat":
			identifier := child.NamedChild(0)
			if identifier == nil || identifier.Kind() != "identifier" {
				result = shellFlagUnresolved // unpacking something other than a plain variable: cannot inspect its keys at all
				continue
			}
			dict, ok := facts.dicts[identifier.Utf8Text(source)]
			if !ok {
				result = shellFlagUnresolved // unpacking a variable this pass never tracked as a dict literal
				continue
			}
			switch dict["shell"] {
			case "true":
				result = shellFlagResolvedTrue
			case "false":
				result = shellFlagResolvedFalse
				// "shell" key absent from a resolved dict: leave result as-is.
			}
		}
	}
	return result
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
		if left == nil || right == nil || left.Kind() != "identifier" {
			return
		}
		switch right.Kind() {
		case "call":
			if sink, ok := reflectiveGetattrSink(right, source, aliases); ok {
				reflective[left.Utf8Text(source)] = sink
			}
		case "subscript":
			if sink, ok := reflectiveVarsSubscriptSink(right, source, aliases); ok {
				reflective[left.Utf8Text(source)] = sink
			}
		case "identifier":
			// A bare alias of a dangerous execution sink itself (`fn = exec`,
			// with no getattr indirection) is just as reflective once called
			// through the local name as the getattr(...) form above.
			resolved := resolvePythonTarget(right.Utf8Text(source), aliases)
			if isDirectDangerousSink(resolved) {
				reflective[left.Utf8Text(source)] = reflectiveSink{target: resolved, name: resolved}
			}
		}
	})
	return reflective
}

// isDirectDangerousSink reports whether resolved (already alias-resolved)
// is itself one of the fixed dynamic-execution sinks that makes a bare
// `fn = <sink>` alias worth tracking as reflective — narrower than "any
// name in pythonCalls", since aliasing e.g. requests.get is ordinary code,
// not reflective execution.
func isDirectDangerousSink(resolved string) bool {
	switch resolved {
	case "exec", "eval", "compile", "__import__", "os.system":
		return true
	default:
		return strings.HasPrefix(resolved, "os.exec")
	}
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
	if !isDangerousReflectiveTarget(module, name) {
		return reflectiveSink{}, false
	}
	return reflectiveSink{target: "getattr(" + module + ", " + name + ")", module: module, name: name}, true
}

// isDangerousReflectiveTarget is the single shared "is this specific
// (module, name) pair a dynamic-execution sink" check reused by every
// reflective-indirection shape this analyzer recognizes (getattr(...),
// vars(...)[...], and any future one) — kept in one place so the exact
// set of dangerous targets can't quietly drift between them.
func isDangerousReflectiveTarget(module, name string) bool {
	return (module == "os" && (name == "system" || strings.HasPrefix(name, "exec"))) ||
		((module == "builtins" || module == "__builtins__") && (name == "exec" || name == "eval" || name == "compile"))
}

// reflectiveVarsSubscriptSink recognizes `vars(module)["name"]` (or
// `vars(__builtins__)["exec"]`) as an equivalent reflective indirection to
// getattr(module, "name") — vars(obj) returns obj's own __dict__, so
// subscripting it by a literal attribute name resolves the same target
// getattr would, just through a different builtin.
func reflectiveVarsSubscriptSink(function *tree_sitter.Node, source []byte, aliases map[string]string) (reflectiveSink, bool) {
	if function == nil || function.Kind() != "subscript" || function.NamedChildCount() != 2 {
		return reflectiveSink{}, false
	}
	base, key := function.NamedChild(0), function.NamedChild(1)
	if base == nil || key == nil || base.Kind() != "call" || key.Kind() != "string" {
		return reflectiveSink{}, false
	}
	baseFunc := base.ChildByFieldName("function")
	baseArgs := base.ChildByFieldName("arguments")
	if baseFunc == nil || resolvePythonTarget(baseFunc.Utf8Text(source), aliases) != "vars" || baseArgs == nil || baseArgs.NamedChildCount() != 1 {
		return reflectiveSink{}, false
	}
	moduleArg := baseArgs.NamedChild(0)
	if moduleArg == nil {
		return reflectiveSink{}, false
	}
	module := resolvePythonTarget(moduleArg.Utf8Text(source), aliases)
	name := strings.Trim(key.Utf8Text(source), `"'`)
	if !isDangerousReflectiveTarget(module, name) {
		return reflectiveSink{}, false
	}
	return reflectiveSink{target: "vars(" + module + ")[" + name + "]", module: module, name: name}, true
}

// reflectiveUnderlyingRule maps a resolved reflective getattr(module, name)
// sink to the same rule a direct, non-reflective call would have produced
// (e.g. getattr(builtins, "exec") behaves like a literal exec(...) call).
// Composing this from the existing pythonCalls table keeps a reflective
// exec/eval/system call classified consistently with its direct form.
func reflectiveUnderlyingRule(sink reflectiveSink) (astRule, bool) {
	switch {
	case (sink.module == "builtins" || sink.module == "__builtins__") && (sink.name == "exec" || sink.name == "eval" || sink.name == "compile"):
		rule, ok := pythonCalls[sink.name]
		return rule, ok
	case sink.module == "os" && (sink.name == "system" || strings.HasPrefix(sink.name, "exec")):
		rule, ok := pythonCalls["os.system"]
		return rule, ok
	case sink.module == "" && isDirectDangerousSink(sink.name):
		// A bare `fn = exec` alias (collectReflectiveAliases' identifier
		// case): the sink already *is* the canonical dangerous name, with
		// no getattr/module indirection to resolve.
		rule, ok := pythonCalls[sink.name]
		if !ok && strings.HasPrefix(sink.name, "os.exec") {
			rule, ok = pythonCalls["os.system"]
		}
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

// assignedVariableName returns the left-hand identifier of the assignment a
// secret-read node is the right-hand side of (e.g. "secret" in
// `secret = os.environ["X"]`), or "" if the node isn't directly assigned to
// a simple variable (used inline, part of a larger expression, etc — the
// authentication-only guard below intentionally does not apply in that
// case, since there is then no single name to trace usage of).
func assignedVariableName(node *tree_sitter.Node, source []byte) string {
	// Node identity can't be compared with == here: each accessor call
	// (Parent, ChildByFieldName, ...) returns a freshly allocated *Node
	// wrapper around the same underlying tree position, so two pointers to
	// "the same" node are never == to each other. Byte-range equality is
	// the correct identity check for this binding.
	start, end := node.StartByte(), node.EndByte()
	for parent := node.Parent(); parent != nil; parent = parent.Parent() {
		switch parent.Kind() {
		case "assignment", "assignment_expression":
			left := parent.ChildByFieldName("left")
			right := parent.ChildByFieldName("right")
			if left != nil && right != nil && right.StartByte() == start && right.EndByte() == end {
				return left.Utf8Text(source)
			}
			return ""
		case "call", "block", "module", "function_definition", "expression_statement":
			return ""
		}
	}
	return ""
}

// secretUsedOnlyForAuthentication reports whether varName's only use(s) in
// source are as the Authorization header value of a fixed-destination GET
// call — the shape every legitimate authenticated API client has — with no
// other appearance anywhere in the file (no second sink, no inclusion in a
// request body/query, no dynamic destination). This is the same invariant
// authenticationOnlyFlow (taint.go) applies to the taint-tracked case,
// applied here directly against the source text since this AST pass does
// not build a full taint graph.
func secretUsedOnlyForAuthentication(varName string, source []byte) bool {
	if varName == "" {
		return false
	}
	text := string(source)
	callPattern := regexp.MustCompile(`(?is)\b(?:requests\.get|http\.get)\s*\([^;]*?\)`)
	matched := false
	remainder := text
	for _, call := range callPattern.FindAllString(text, -1) {
		if !strings.Contains(call, varName) {
			continue
		}
		lower := strings.ToLower(call)
		if !strings.Contains(lower, "authorization") {
			return false
		}
		for _, payload := range []string{"data=", "json=", "body=", "content="} {
			if strings.Contains(lower, payload) {
				return false
			}
		}
		matched = true
		remainder = strings.Replace(remainder, call, "", 1)
	}
	if !matched {
		return false
	}
	// After removing every qualifying call, varName must appear at most once
	// more (its own assignment) — any further occurrence means it reaches
	// somewhere this check didn't already approve.
	return strings.Count(remainder, varName) <= 1
}
