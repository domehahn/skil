package analyzer

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_ruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"

	"github.com/domehahn/skil/pkg/skil"
)

// RubyAST analyzes a real Ruby syntax tree. It never requires, loads, or
// executes the scanned file. Unlike PythonAST, it does not attempt
// import-alias or reflective-variable resolution — a deliberately
// proportionate scope for an additional-language pass added on demand
// rather than a flagship analyzer; it resolves only literal call targets
// (bare calls and receiver.method calls) directly from the syntax tree.
type RubyAST struct{}

func NewRubyAST() *RubyAST { return &RubyAST{} }

func (r *RubyAST) Rules() []skil.Rule {
	return []skil.Rule{{
		ID: "SKIL-RB-004", Title: "Reflective Ruby method dispatch", Category: "dynamic-execution",
		Severity: skil.SeverityMedium, Analysis: "ast", AppliesTo: []string{"rb"},
		Description: "Ruby dynamically dispatches a method whose name is not a literal symbol or string.",
		Remediation: "Use an explicit, reviewable method call, or validate the method name against an allowlist.",
	}}
}

func (r *RubyAST) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.ruby-ast", Version: "1.0.0",
		Domain: "code", Subdomain: "ast",
		Categories:    []string{"dynamic-execution", "data-boundary"},
		AnalysisTypes: []string{"ast"}, SupportedTypes: []string{"rb"},
	}
}

func rbRule(id, title, description, remediation, capability string, severity skil.Severity) astRule {
	category := "dynamic-execution"
	if id == "SKIL-NET-001" || id == "SKIL-SEC-001" {
		category = "data-boundary"
	}
	return astRule{id, title, category, description, remediation, capability, severity, .95}
}

// rubyCalls maps a resolved call target (bare "eval", or "Receiver.method"
// for a receiver-qualified call — Ruby's `::` scope-resolution operator,
// e.g. "Net::HTTP", is kept verbatim in the receiver text) to the control
// it represents. Reused rule IDs (SKIL-NET-001, SKIL-SEC-001) match the
// exact vocabulary PythonAST/StructuredAST already use for the same
// underlying concern in other languages.
var rubyCalls = map[string]astRule{
	"eval":          rbRule("SKIL-RB-001", "Dynamic Ruby execution", "Ruby evaluates dynamic source text.", "Replace eval with a constrained parser.", "commands.execute", skil.SeverityHigh),
	"instance_eval": rbRule("SKIL-RB-001", "Dynamic Ruby execution", "Ruby evaluates dynamic source text against an object's singleton context.", "Replace instance_eval with a constrained parser.", "commands.execute", skil.SeverityHigh),
	"class_eval":    rbRule("SKIL-RB-001", "Dynamic Ruby execution", "Ruby evaluates dynamic source text against a class definition.", "Replace class_eval with a constrained parser.", "commands.execute", skil.SeverityHigh),
	"module_eval":   rbRule("SKIL-RB-001", "Dynamic Ruby execution", "Ruby evaluates dynamic source text against a module definition.", "Replace module_eval with a constrained parser.", "commands.execute", skil.SeverityHigh),

	"system":          rbRule("SKIL-RB-002", "Ruby process execution", "Ruby starts an operating-system process.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"exec":            rbRule("SKIL-RB-002", "Ruby process execution", "Ruby replaces the current process with a new one.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"Kernel.exec":     rbRule("SKIL-RB-002", "Ruby process execution", "Ruby replaces the current process with a new one.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"Kernel.system":   rbRule("SKIL-RB-002", "Ruby process execution", "Ruby starts an operating-system process.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"IO.popen":        rbRule("SKIL-RB-002", "Ruby process execution", "Ruby starts an operating-system process with a piped I/O stream.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"Open3.capture2":  rbRule("SKIL-RB-002", "Ruby process execution", "Ruby starts an operating-system process.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"Open3.capture2e": rbRule("SKIL-RB-002", "Ruby process execution", "Ruby starts an operating-system process.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"Open3.capture3":  rbRule("SKIL-RB-002", "Ruby process execution", "Ruby starts an operating-system process.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),
	"Open3.popen3":    rbRule("SKIL-RB-002", "Ruby process execution", "Ruby starts an operating-system process with piped I/O streams.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh),

	"Marshal.load":    rbRule("SKIL-RB-003", "Unsafe Ruby deserialization", "Marshal may execute behavior while deserializing.", "Use a non-executable data format.", "", skil.SeverityHigh),
	"Marshal.restore": rbRule("SKIL-RB-003", "Unsafe Ruby deserialization", "Marshal may execute behavior while deserializing.", "Use a non-executable data format.", "", skil.SeverityHigh),
	"YAML.load":       rbRule("SKIL-RB-003", "Unsafe Ruby deserialization", "YAML.load may instantiate arbitrary Ruby objects from untrusted input.", "Use YAML.safe_load with an explicit permitted-class allowlist.", "", skil.SeverityHigh),
	"Psych.load":      rbRule("SKIL-RB-003", "Unsafe Ruby deserialization", "Psych.load may instantiate arbitrary Ruby objects from untrusted input.", "Use Psych.safe_load with an explicit permitted-class allowlist.", "", skil.SeverityHigh),

	"Net::HTTP.get":  rbRule("SKIL-NET-001", "Outbound network operation", "Ruby performs an outbound network request.", "Declare and constrain outbound network access.", "network.outbound", skil.SeverityMedium),
	"Net::HTTP.post": rbRule("SKIL-NET-001", "Outbound network operation", "Ruby performs an outbound network request.", "Declare and constrain outbound network access.", "network.outbound", skil.SeverityMedium),
	"URI.open":       rbRule("SKIL-NET-001", "Outbound network operation", "Ruby performs an outbound network request via open-uri.", "Declare and constrain outbound network access.", "network.outbound", skil.SeverityMedium),
	"HTTParty.get":   rbRule("SKIL-NET-001", "Outbound network operation", "Ruby performs an outbound network request.", "Declare and constrain outbound network access.", "network.outbound", skil.SeverityMedium),
	"HTTParty.post":  rbRule("SKIL-NET-001", "Outbound network operation", "Ruby performs an outbound network request.", "Declare and constrain outbound network access.", "network.outbound", skil.SeverityMedium),

	"ENV.fetch": rbRule("SKIL-SEC-001", "Environment or secret read", "Ruby reads an environment variable that may contain secrets.", "Declare exact variables and avoid broad secret access.", "secrets.read", skil.SeverityHigh),
}

var reflectiveRubyDispatch = map[string]bool{"send": true, "__send__": true, "public_send": true}

func (r *RubyAST) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	findings, _, err := r.AnalyzeCapabilities(ctx, ac)
	return findings, err
}

func (r *RubyAST) AnalyzeCapabilities(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, []skil.CapabilityObservation, error) {
	var out []skil.Finding
	var observations []skil.CapabilityObservation
	for _, file := range ac.Artifact.Files {
		if extension(file.Path) != "rb" {
			continue
		}
		tree, err := parseStructured(ctx, file.Data, tree_sitter_ruby.Language())
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		emit := func(node *tree_sitter.Node, target string, rule astRule) {
			rp := RulePattern{Rule: skil.Rule{ID: rule.id, Title: rule.title, Category: rule.category,
				Severity: rule.severity, Description: rule.description, Analysis: "ast", AppliesTo: []string{"rb"},
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
			case "secrets.read":
				if literal != "" {
					finding.Evidence["secret"] = literal
					finding.Evidence["environment"] = literal
					value = literal
				}
			}
			out = append(out, finding)
			start2 := node.StartPosition()
			obs := skil.CapabilityObservation{
				Capability: rule.capability, Value: value, Analyzer: "builtin.ruby-ast",
				Location: skil.Location{File: file.Path, StartLine: int(start2.Row) + 1, EndLine: int(start2.Row) + 1},
				Evidence: map[string]any{"call_target": target, "node_type": node.Kind()},
			}
			if rule.capability != "" {
				observations = append(observations, obs)
			}
			if rule.capability == "secrets.read" && value != "" {
				obs2 := obs
				obs2.Capability = "environment.read"
				observations = append(observations, obs2)
			}
		}
		walkNode(tree.RootNode(), func(node *tree_sitter.Node) {
			switch node.Kind() {
			case "subshell":
				// Backtick (`cmd`) and %x{cmd} literals both parse as
				// "subshell" — Ruby's only paren-less, receiver-less
				// process-execution syntax, with no equivalent "call"
				// node to resolve a target from.
				rule := rbRule("SKIL-RB-002", "Ruby process execution", "Ruby executes a shell command via a backtick or %x{} literal.", "Use a constrained API and explicit argument allowlists.", "commands.execute", skil.SeverityHigh)
				emit(node, "`...`", rule)
				return
			case "element_reference":
				object := node.ChildByFieldName("object")
				if object == nil || object.Utf8Text(file.Data) != "ENV" {
					return
				}
				rule := rbRule("SKIL-SEC-001", "Environment or secret read", "Ruby reads an environment variable that may contain secrets.", "Declare exact variables and avoid broad secret access.", "secrets.read", skil.SeverityHigh)
				emit(node, "ENV[]", rule)
				return
			case "call":
				// fall through below
			default:
				return
			}
			method := node.ChildByFieldName("method")
			if method == nil {
				return
			}
			methodName := method.Utf8Text(file.Data)
			receiver := node.ChildByFieldName("receiver")
			target := methodName
			if receiver != nil {
				target = receiver.Utf8Text(file.Data) + "." + methodName
			}
			if reflectiveRubyDispatch[methodName] && receiver == nil {
				if dynamicRubyDispatch(node) {
					emit(node, target, rbRule("SKIL-RB-004", "Reflective Ruby method dispatch", "Ruby dynamically dispatches a method whose name is not a literal symbol or string.", "Use an explicit, reviewable method call, or validate the method name against an allowlist.", "", skil.SeverityMedium))
				}
				return
			}
			if rule, found := rubyCalls[target]; found {
				emit(node, target, rule)
			}
		})
		tree.Close()
	}
	return out, observations, nil
}

// dynamicRubyDispatch reports whether send/__send__/public_send's first
// argument is anything other than a literal symbol or string — i.e.
// whether the dispatched method name is actually dynamic rather than just
// an alternate literal-call syntax.
func dynamicRubyDispatch(call *tree_sitter.Node) bool {
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return false
	}
	switch args.NamedChild(0).Kind() {
	case "simple_symbol", "string":
		return false
	default:
		return true
	}
}
