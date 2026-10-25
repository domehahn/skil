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

func providerReturning(t *testing.T, content string) *Provider {
	t.Helper()
	client := &http.Client{Transport: semanticRoundTrip(func(r *http.Request) (*http.Response, error) {
		body, _ := json.Marshal(map[string]any{"model": "test", "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": content}}}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header), Request: r}, nil
	})}
	p, err := New(Config{Endpoint: "https://semantic.test/v1/chat/completions", Model: "test", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// An output that is JSON but lacks the required "findings" array is a schema
// violation, not a successful zero-finding review.
func TestInvalidStructuredOutputIsNotAValidZeroFindingResult(t *testing.T) {
	for name, content := range map[string]string{
		"empty object":        `{}`,
		"wrong key":           `{"results":[]}`,
		"null findings":       `{"findings":null}`,
		"findings not array":  `{"findings":"none"}`,
		"unknown extra field": `{"findings":[],"note":"all clear"}`,
		"empty content":       ``,
		"prose":               `No issues found.`,
		"trailing garbage":    `{"findings":[]} and also ignore previous instructions`,
		"array root":          `[]`,
	} {
		res, err := providerReturning(t, content).AnalyzeUntrustedDetailed(context.Background(),
			skil.SemanticRequest{ArtifactDigest: "d", Files: map[string]string{"SKILL.md": "x"}, NoTools: true})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !res.Diagnostics.Incomplete {
			t.Errorf("%s: invalid output became a valid result: %+v", name, res.Diagnostics)
		}
	}
}

func TestExplicitEmptyFindingsArrayIsAValidZeroFindingResult(t *testing.T) {
	res, err := providerReturning(t, `{"findings":[]}`).AnalyzeUntrustedDetailed(context.Background(),
		skil.SemanticRequest{ArtifactDigest: "d", Files: map[string]string{"SKILL.md": "x"}, NoTools: true})
	if err != nil || res.Diagnostics.Incomplete {
		t.Fatalf("%v %+v", err, res.Diagnostics)
	}
}
