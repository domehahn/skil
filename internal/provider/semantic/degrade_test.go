package semantic

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func newTestProvider(t *testing.T, roundTrip func(*http.Request) (*http.Response, error)) *Provider {
	t.Helper()
	provider, err := New(Config{
		Endpoint: "https://semantic.test/v1/chat/completions", Model: "test",
		HTTPClient: &http.Client{Transport: semanticRoundTrip(roundTrip)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func jsonResponse(status int, body string) (*http.Response, error) {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

// TestTruncatedResponseDegradesRatherThanErrors is the core new invariant:
// a provider reporting finish_reason=="length" (it hit the output-token
// limit before finishing) must never be parsed as a complete response,
// and must never propagate as a Go error — only as an incomplete,
// degraded pass.
func TestTruncatedResponseDegradesRatherThanErrors(t *testing.T) {
	provider := newTestProvider(t, func(*http.Request) (*http.Response, error) {
		body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message":       map[string]any{"content": `{"findings":[{"control":"semantic_secur`}, // truncated mid-JSON
			"finish_reason": "length",
		}}})
		return jsonResponse(200, string(body))
	})
	result, err := provider.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{
		ArtifactDigest: "abc", Files: map[string]string{"SKILL.md": "x"}, NoTools: true,
	})
	if err != nil {
		t.Fatalf("a truncated response must degrade, not error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("a truncated response must produce zero findings, even if a valid-looking prefix survived: %#v", result.Findings)
	}
	if !result.Diagnostics.Incomplete || result.Diagnostics.Rejected == 0 {
		t.Fatalf("expected an incomplete, degraded diagnostic: %#v", result.Diagnostics)
	}
	if len(result.Diagnostics.Errors) == 0 || !strings.Contains(result.Diagnostics.Errors[0].Message, "length") {
		t.Fatalf("expected the diagnostic to name the truncation reason: %#v", result.Diagnostics.Errors)
	}
}

func TestMalformedStructuredOutputDegradesRatherThanErrors(t *testing.T) {
	provider := newTestProvider(t, func(*http.Request) (*http.Response, error) {
		body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"content": `not json at all`},
		}}})
		return jsonResponse(200, string(body))
	})
	result, err := provider.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{
		ArtifactDigest: "abc", Files: map[string]string{"SKILL.md": "x"}, NoTools: true,
	})
	if err != nil {
		t.Fatalf("malformed structured output must degrade, not error: %v", err)
	}
	if !result.Diagnostics.Incomplete {
		t.Fatalf("expected an incomplete diagnostic: %#v", result.Diagnostics)
	}
}

func TestHTTPErrorStatusDegradesRatherThanErrors(t *testing.T) {
	provider := newTestProvider(t, func(*http.Request) (*http.Response, error) {
		return jsonResponse(503, `{"error":"upstream unavailable"}`)
	})
	result, err := provider.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{
		ArtifactDigest: "abc", Files: map[string]string{"SKILL.md": "x"}, NoTools: true,
	})
	if err != nil {
		t.Fatalf("an HTTP error status must degrade, not error: %v", err)
	}
	if !result.Diagnostics.Incomplete {
		t.Fatalf("expected an incomplete diagnostic: %#v", result.Diagnostics)
	}
}

func TestTransportFailureDegradesRatherThanErrors(t *testing.T) {
	provider := newTestProvider(t, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})
	result, err := provider.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{
		ArtifactDigest: "abc", Files: map[string]string{"SKILL.md": "x"}, NoTools: true,
	})
	if err != nil {
		t.Fatalf("a transport failure must degrade, not error: %v", err)
	}
	if !result.Diagnostics.Incomplete {
		t.Fatalf("expected an incomplete diagnostic: %#v", result.Diagnostics)
	}
}

func TestOversizedResponseDegradesRatherThanErrors(t *testing.T) {
	huge := strings.Repeat("a", maxResponse+1024)
	provider := newTestProvider(t, func(*http.Request) (*http.Response, error) {
		return jsonResponse(200, huge)
	})
	result, err := provider.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{
		ArtifactDigest: "abc", Files: map[string]string{"SKILL.md": "x"}, NoTools: true,
	})
	if err != nil {
		t.Fatalf("an oversized response must degrade, not error: %v", err)
	}
	if !result.Diagnostics.Incomplete {
		t.Fatalf("expected an incomplete diagnostic: %#v", result.Diagnostics)
	}
}

func TestCompleteResponseIsNotFlaggedIncomplete(t *testing.T) {
	provider := newTestProvider(t, func(*http.Request) (*http.Response, error) {
		content := `{"findings":[]}`
		body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"content": content}, "finish_reason": "stop",
		}}})
		return jsonResponse(200, string(body))
	})
	result, err := provider.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{
		ArtifactDigest: "abc", Files: map[string]string{"SKILL.md": "x"}, NoTools: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Diagnostics.Incomplete {
		t.Fatalf("a complete, well-formed response must not be flagged incomplete: %#v", result.Diagnostics)
	}
}
