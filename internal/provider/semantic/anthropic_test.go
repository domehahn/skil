package semantic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestAnthropicSemanticProviderUsesNoToolsAndValidatesOutput(t *testing.T) {
	client := &http.Client{Transport: semanticRoundTrip(func(request *http.Request) (*http.Response, error) {
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["tools"] != nil || request.Header.Get("Anthropic-Version") == "" {
			t.Fatalf("unsafe Anthropic request: %#v", payload)
		}
		finding := `{"findings":[{"control":"semantic_quality","severity":"MEDIUM","confidence":0.8,"title":"Ambiguous","message":"unclear","file":"SKILL.md","start_line":1,"end_line":1,"remediation":"clarify"}]}`
		body, _ := json.Marshal(map[string]any{"content": []any{map[string]string{"type": "text", "text": finding}}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
	})}
	provider, err := NewAnthropic(AnthropicConfig{Endpoint: "https://semantic.test/v1/messages", Model: "test", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := provider.AnalyzeUntrusted(context.Background(), skil.SemanticRequest{
		ArtifactDigest: "abc", Files: map[string]string{"SKILL.md": "ambiguous"}, Focus: "quality", NoTools: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "SKIL-SEM-QUALITY" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestAnthropicProxyRewritesAuthenticationAndPayload(t *testing.T) {
	var received map[string]any
	client := &http.Client{Transport: semanticRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer proxy-token" || request.Header.Get("X-Api-Key") != "" {
			t.Errorf("unexpected proxy authentication headers: %#v", request.Header)
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
			`{"content":[{"type":"text","text":"{\"findings\":[]}"}]}`,
		)), Header: make(http.Header)}, nil
	})}
	provider, err := NewAnthropicProxy(AnthropicProxyConfig{
		Endpoint: "https://proxy.test/raw-predict", Model: "claude-test", BearerToken: "proxy-token",
		HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.AnalyzeUntrusted(context.Background(), skil.SemanticRequest{
		Focus: "security", NoTools: true, Files: map[string]string{"SKILL.md": "safe"},
	}); err != nil {
		t.Fatal(err)
	}
	if received["model"] != nil || received["anthropic_version"] != "vertex-2023-10-16" {
		t.Fatalf("unexpected proxy payload: %#v", received)
	}
}
