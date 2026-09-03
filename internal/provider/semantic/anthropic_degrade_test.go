package semantic

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestAnthropicStopReasonMaxTokensDegradesRatherThanErrors(t *testing.T) {
	client := &http.Client{Transport: semanticRoundTrip(func(*http.Request) (*http.Response, error) {
		body, _ := json.Marshal(map[string]any{
			"content":     []any{map[string]any{"type": "text", "text": `{"findings":[{"contro`}}, // truncated mid-JSON
			"stop_reason": "max_tokens",
		})
		return jsonResponse(200, string(body))
	})}
	provider, err := NewAnthropic(AnthropicConfig{Endpoint: "https://semantic.test/v1/messages", Model: "test", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{
		ArtifactDigest: "abc", Files: map[string]string{"SKILL.md": "x"}, NoTools: true,
	})
	if err != nil {
		t.Fatalf("stop_reason=max_tokens must degrade, not error: %v", err)
	}
	if len(result.Findings) != 0 || !result.Diagnostics.Incomplete {
		t.Fatalf("expected zero findings and an incomplete diagnostic: %#v", result)
	}
}
