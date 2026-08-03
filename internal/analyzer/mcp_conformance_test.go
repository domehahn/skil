package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func mcpFindings(t *testing.T, path, content string) []skil.Finding {
	t.Helper()
	findings, err := NewMCP().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith(path, content)})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestMCPTokenPassthroughIsDetected(t *testing.T) {
	content := "import requests\n\ndef mcp_handler(request):\n    headers = request.headers\n    return requests.post(downstream_url, headers=headers)\n"
	findings := mcpFindings(t, "mcp_server.py", content)
	if !hasRule(findings, "SKIL-MCP-008") {
		t.Fatalf("expected MCP token passthrough to be detected: %#v", findings)
	}
}

func TestMCPScopedHeadersAreSafe(t *testing.T) {
	content := "import requests\n\ndef mcp_handler(request):\n    return requests.post(downstream_url, headers={'Content-Type': 'application/json'})\n"
	findings := mcpFindings(t, "mcp_server.py", content)
	if hasRule(findings, "SKIL-MCP-008") {
		t.Fatalf("explicitly scoped headers should not fire: %#v", findings)
	}
}

func TestMCPToolControlledFetchIsDetected(t *testing.T) {
	content := "import requests\n\ndef fetch_tool(url):\n    return requests.get(url)\n"
	findings := mcpFindings(t, "mcp_server.py", content)
	if !hasRule(findings, "SKIL-MCP-009") {
		t.Fatalf("expected a tool-controlled URL fetch to be detected: %#v", findings)
	}
}

func TestMCPFixedEndpointFetchIsSafe(t *testing.T) {
	content := "import requests\n\ndef fetch_tool():\n    return requests.get('https://api.example.com/status')\n"
	findings := mcpFindings(t, "mcp_server.py", content)
	if hasRule(findings, "SKIL-MCP-009") {
		t.Fatalf("a fixed, literal endpoint fetch should not fire: %#v", findings)
	}
}

func TestMCPOverbroadScopeIsDetected(t *testing.T) {
	content := `{"mcpServers":{"reviewer":{"command":"reviewer","args":["-y","reviewer@1.0.0"],"oauth":{"scope":"admin"}}}}`
	findings := mcpFindings(t, "mcp.json", content)
	if !hasRule(findings, "SKIL-MCP-010") {
		t.Fatalf("expected an overly broad OAuth scope to be detected: %#v", findings)
	}
}

func TestMCPNarrowScopeIsSafe(t *testing.T) {
	content := `{"mcpServers":{"reviewer":{"command":"reviewer","args":["-y","reviewer@1.0.0"],"oauth":{"scope":"repo:read"}}}}`
	findings := mcpFindings(t, "mcp.json", content)
	if hasRule(findings, "SKIL-MCP-010") {
		t.Fatalf("a narrowly scoped OAuth grant should not fire: %#v", findings)
	}
}
