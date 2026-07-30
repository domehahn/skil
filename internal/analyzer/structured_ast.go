package analyzer

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tree_sitter_typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"

	"github.com/domehahn/skil/pkg/skil"
)

// StructuredAST applies security controls only to syntactic command,
// expression, and call nodes. This avoids comment/string matches while keeping
// the control vocabulary shared with other language analyzers.
type StructuredAST struct {
	codeRules []RulePattern
}

func NewStructuredAST() *StructuredAST {
	return &StructuredAST{codeRules: NewCode().rules}
}

func (s *StructuredAST) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.structured-ast", Version: "1.0.0",
		Domain: "code", Subdomain: "ast",
		Categories:     []string{"dynamic-execution", "dependency-trust", "privilege-boundary", "data-boundary"},
		AnalysisTypes:  []string{"ast", "static-code"},
		SupportedTypes: []string{"sh", "bash", "js", "jsx", "ts", "tsx"},
	}
}

func (s *StructuredAST) Rules() []skil.Rule {
	return []skil.Rule{{
		ID: "SKIL-JS-002", Title: "Dynamic JavaScript execution", Category: "dynamic-execution",
		Severity: skil.SeverityHigh, Analysis: "ast", AppliesTo: []string{"js", "jsx", "ts", "tsx"},
		Description: "JavaScript or TypeScript dynamically evaluates source text.",
		Remediation: "Remove eval and dynamic Function construction; use a constrained parser.",
	}}
}

func (s *StructuredAST) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		ext := extension(file.Path)
		language, family := structuredLanguage(ext)
		if language == nil {
			continue
		}
		tree, err := parseStructured(ctx, file.Data, language)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		walkNode(tree.RootNode(), func(node *tree_sitter.Node) {
			if !structuredSecurityNode(family, node.Kind()) {
				return
			}
			text := node.Utf8Text(file.Data)
			for _, control := range s.codeRules {
				if !controlForFamily(control.Rule.ID, family) || !control.Pattern.MatchString(text) {
					continue
				}
				out = append(out, structuredFinding(control, file, node, text))
			}
			if family == "javascript" && node.Kind() == "call_expression" {
				function := node.ChildByFieldName("function")
				if function != nil {
					target := strings.ReplaceAll(function.Utf8Text(file.Data), "?.", ".")
					if target == "eval" || target == "Function" || target == "globalThis.eval" {
						rule := RulePattern{Rule: s.Rules()[0], Confidence: .99}
						out = append(out, structuredFinding(rule, file, node, text))
					}
				}
			}
		})
		tree.Close()
	}
	return out, nil
}

func structuredLanguage(extension string) (unsafe.Pointer, string) {
	switch extension {
	case "js", "jsx":
		return tree_sitter_javascript.Language(), "javascript"
	case "ts":
		return tree_sitter_typescript.LanguageTypescript(), "javascript"
	case "tsx":
		return tree_sitter_typescript.LanguageTSX(), "javascript"
	case "sh", "bash":
		return tree_sitter_bash.Language(), "shell"
	default:
		return nil, ""
	}
}

func parseStructured(ctx context.Context, source []byte, language unsafe.Pointer) (*tree_sitter.Tree, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(language)); err != nil {
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

func structuredSecurityNode(family, kind string) bool {
	if family == "shell" {
		return kind == "command" || kind == "pipeline"
	}
	switch kind {
	case "call_expression", "new_expression", "member_expression", "subscript_expression":
		return true
	default:
		return false
	}
}

func controlForFamily(id, family string) bool {
	if family == "shell" {
		return strings.HasPrefix(id, "SKIL-SH-") || id == "SKIL-NET-001" ||
			id == "SKIL-FS-001" || id == "SKIL-SEC-001" ||
			id == "SKIL-PERSISTENCE-STARTUP" || id == "SKIL-CONTAINER-TRUST"
	}
	return strings.HasPrefix(id, "SKIL-JS-") || id == "SKIL-NET-001" ||
		id == "SKIL-FS-001" || id == "SKIL-SEC-001"
}

func structuredFinding(rule RulePattern, file skil.File, node *tree_sitter.Node, text string) skil.Finding {
	start, end := node.StartPosition(), node.EndPosition()
	finding := makeFinding(rule, file, int(start.Row)+1, text)
	finding.Location.EndLine = int(end.Row) + 1
	finding.Evidence["node_type"] = node.Kind()
	switch rule.Rule.ID {
	case "SKIL-JS-001", "SKIL-JS-002", "SKIL-SH-001", "SKIL-SH-002", "SKIL-SH-003", "SKIL-SH-004":
		finding.Evidence["capability"] = "commands.execute"
	case "SKIL-PERSISTENCE-STARTUP":
		finding.Evidence["capability"] = "persistence"
	case "SKIL-NET-001":
		finding.Evidence["capability"] = "network.outbound"
	case "SKIL-FS-001":
		finding.Evidence["capability"] = "filesystem.write"
	case "SKIL-SEC-001":
		finding.Evidence["capability"] = "secrets.read"
	}
	return finding
}
