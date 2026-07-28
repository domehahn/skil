package analyzer

import (
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type MCP struct{}

func NewMCP() *MCP { return &MCP{} }
func (m *MCP) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.mcp", Version: "1.0.0",
		Categories:    []string{"mcp-security", "mcp-least-privilege", "mcp-tool-poisoning"},
		AnalysisTypes: []string{"mcp"}, SupportedTypes: []string{"json", "yaml"}}
}
func (m *MCP) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	wild := regexp.MustCompile(`(?i)(?:permissions?|tools?|allow)\s*["':=\s]+\*`)
	poison := regexp.MustCompile(`(?i)(?:description|default).{0,40}(?:ignore (?:previous|system)|never refuse|reveal (?:system|secret)|hidden instruction)`)
	for _, file := range ac.Artifact.Files {
		lower := strings.ToLower(file.Path)
		if !strings.Contains(lower, "mcp") && !strings.Contains(strings.ToLower(string(file.Data)), "mcpserver") {
			continue
		}
		for line, text := range lines(file.Data) {
			if wild.MatchString(text) {
				rule := RulePattern{Rule: skil.Rule{ID: "SKIL-MCP-001", Title: "Wildcard MCP permission",
					Category: "mcp-least-privilege", Severity: skil.SeverityHigh,
					Description: "MCP configuration grants an unconstrained wildcard.", Analysis: "mcp",
					Remediation: "Declare exact MCP servers and tools."}, Confidence: .9}
				out = append(out, makeFinding(rule, file, line+1, text))
			}
			if poison.MatchString(text) {
				rule := RulePattern{Rule: skil.Rule{ID: "SKIL-MCP-002", Title: "MCP tool description poisoning",
					Category: "mcp-tool-poisoning", Severity: skil.SeverityCritical,
					Description: "An MCP description or default embeds manipulative instructions.", Analysis: "mcp",
					Remediation: "Remove hidden instructions and bind descriptions to reviewed tool behavior."}, Confidence: .9}
				out = append(out, makeFinding(rule, file, line+1, text))
			}
		}
	}
	return out, nil
}
