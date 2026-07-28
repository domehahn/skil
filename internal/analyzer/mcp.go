package analyzer

import (
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

type MCP struct{}

func NewMCP() *MCP { return &MCP{} }
func (m *MCP) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.mcp", Version: "1.0.0",
		Categories:    []string{"tool-protocol"},
		AnalysisTypes: []string{"mcp"}, SupportedTypes: []string{"json", "yaml"}}
}
func (m *MCP) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	wild := regexp.MustCompile(`(?i)(?:permissions?|tools?|allow)\s*["':=\s]+\*`)
	poison := regexp.MustCompile(`(?i)(?:description|default).{0,40}(?:ignore (?:previous|system)|never refuse|reveal (?:system|secret)|hidden instruction)`)
	poisonValue := regexp.MustCompile(`(?i)(?:ignore (?:previous|system)|never refuse|reveal (?:system|secret)|hidden instruction)`)
	for _, file := range ac.Artifact.Files {
		lower := strings.ToLower(file.Path)
		if !strings.Contains(lower, "mcp") && !strings.Contains(strings.ToLower(string(file.Data)), "mcpserver") {
			continue
		}
		var document any
		if err := yaml.Unmarshal(file.Data, &document); err == nil && isStructuredMCPDocument(document) {
			seen := map[string]bool{}
			walkMCPDocument(document, func(key string, value any) {
				normalized := strings.ToLower(strings.TrimSpace(key))
				line, text := lineContaining(file.Data, key)
				if mcpPermissionKey(normalized) && containsWildcard(value) {
					emitMCPFinding(&out, seen, file, line, text, RulePattern{Rule: skil.Rule{
						ID: "SKIL-MCP-001", Title: "Wildcard MCP permission",
						Category: "tool-protocol", Severity: skil.SeverityHigh,
						Description: "MCP configuration grants an unconstrained wildcard.", Analysis: "mcp",
						Remediation: "Declare exact MCP servers and tools."}, Confidence: .99})
				}
				if (normalized == "description" || normalized == "default") && poisonValue.MatchString(stringValue(value)) {
					emitMCPFinding(&out, seen, file, line, text, RulePattern{Rule: skil.Rule{
						ID: "SKIL-MCP-002", Title: "MCP tool description poisoning",
						Category: "tool-protocol", Severity: skil.SeverityCritical,
						Description: "An MCP description or default embeds manipulative instructions.", Analysis: "mcp",
						Remediation: "Remove hidden instructions and bind descriptions to reviewed tool behavior."}, Confidence: .99})
				}
			})
			continue
		}
		for line, text := range lines(file.Data) {
			if wild.MatchString(text) {
				rule := RulePattern{Rule: skil.Rule{ID: "SKIL-MCP-001", Title: "Wildcard MCP permission",
					Category: "tool-protocol", Severity: skil.SeverityHigh,
					Description: "MCP configuration grants an unconstrained wildcard.", Analysis: "mcp",
					Remediation: "Declare exact MCP servers and tools."}, Confidence: .9}
				out = append(out, makeFinding(rule, file, line+1, text))
			}
			if poison.MatchString(text) {
				rule := RulePattern{Rule: skil.Rule{ID: "SKIL-MCP-002", Title: "MCP tool description poisoning",
					Category: "tool-protocol", Severity: skil.SeverityCritical,
					Description: "An MCP description or default embeds manipulative instructions.", Analysis: "mcp",
					Remediation: "Remove hidden instructions and bind descriptions to reviewed tool behavior."}, Confidence: .9}
				out = append(out, makeFinding(rule, file, line+1, text))
			}
		}
	}
	return out, nil
}

func isStructuredMCPDocument(value any) bool {
	switch value.(type) {
	case map[string]any, []any:
		return true
	default:
		return false
	}
}

func walkMCPDocument(value any, visit func(string, any)) {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			visit(key, child)
			walkMCPDocument(child, visit)
		}
	case []any:
		for _, child := range item {
			walkMCPDocument(child, visit)
		}
	}
}

func mcpPermissionKey(key string) bool {
	switch key {
	case "permission", "permissions", "tool", "tools", "allow", "allowed_tools":
		return true
	default:
		return false
	}
}

func containsWildcard(value any) bool {
	switch item := value.(type) {
	case string:
		return strings.TrimSpace(item) == "*"
	case []any:
		for _, child := range item {
			if containsWildcard(child) {
				return true
			}
		}
	case map[string]any:
		if _, ok := item["*"]; ok {
			return true
		}
		for _, child := range item {
			if containsWildcard(child) {
				return true
			}
		}
	}
	return false
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func lineContaining(data []byte, value string) (int, string) {
	needle := strings.ToLower(value)
	for index, line := range lines(data) {
		if strings.Contains(strings.ToLower(line), needle) {
			return index + 1, line
		}
	}
	return 1, value
}

func emitMCPFinding(out *[]skil.Finding, seen map[string]bool, file skil.File, line int, text string, rule RulePattern) {
	key := rule.Rule.ID + ":" + file.Path + ":" + strings.TrimSpace(text)
	if seen[key] {
		return
	}
	seen[key] = true
	*out = append(*out, makeFinding(rule, file, line, text))
}
