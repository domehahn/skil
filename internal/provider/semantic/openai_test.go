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

func TestStructuredNoToolSemanticRequest(t *testing.T) {
	client := &http.Client{Transport: semanticRoundTrip(func(r *http.Request) (*http.Response, error) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request["tool_choice"] != "none" || request["tools"] != nil || request["response_format"] == nil {
			t.Errorf("unsafe semantic request: %#v", request)
		}
		content := `{"findings":[{"control":"scope_expansion","severity":"HIGH","confidence":0.9,"title":"Broad agency","message":"Unbounded action","file":"SKILL.md","start_line":1,"end_line":1,"remediation":"Constrain it"}]}`
		body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": content}}}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
	})}
	provider, err := New(Config{Endpoint: "https://semantic.test/v1/chat/completions", Model: "test", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := provider.AnalyzeUntrusted(context.Background(), skil.SemanticRequest{ArtifactDigest: "abc",
		Files: map[string]string{"SKILL.md": "do things"}, NoTools: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "SKIL-INTENT-SCOPE" {
		t.Fatalf("%#v", findings)
	}
}

type semanticRoundTrip func(*http.Request) (*http.Response, error)

func (f semanticRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSemanticRejectsToolsAndUnknownFiles(t *testing.T) {
	provider, err := New(Config{Endpoint: "https://example.com/v1/chat/completions", Model: "test", HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.AnalyzeUntrusted(context.Background(), skil.SemanticRequest{}); err == nil {
		t.Fatal("expected NoTools rejection")
	}
	if _, err := New(Config{Endpoint: "http://169.254.169.254/latest", Model: "x"}); err == nil {
		t.Fatal("expected metadata endpoint rejection")
	}
}

func TestNativeIntentControlsHaveDistinctRuleIDs(t *testing.T) {
	want := map[string]string{
		"description_mismatch":      "SKIL-INTENT-DESCRIPTION",
		"context_misuse":            "SKIL-INTENT-CONTEXT",
		"scope_expansion":           "SKIL-INTENT-SCOPE",
		"implementation_divergence": "SKIL-INTENT-IMPLEMENTATION",
	}
	for control, ruleID := range want {
		items := []semanticFinding{{
			Control: control, Severity: "HIGH", Confidence: .8,
			Title: control, Message: "evidence", File: "SKILL.md", StartLine: 1, EndLine: 1,
			Remediation: "review",
		}}
		findings, err := normalizeFindings(items, skil.SemanticRequest{
			ArtifactDigest: "abc", Files: map[string]string{"SKILL.md": "content"},
		}, "test")
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 1 || findings[0].RuleID != ruleID {
			t.Fatalf("%s normalized to %#v", control, findings)
		}
	}
}
