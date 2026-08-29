package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAssureProviderValidatesEndpointAndIdentity(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model": "gpt-4o-mini", "choices": [{"message": {"content": "pong"}}]}`))
	}))
	defer ts.Close()

	p, err := New(Config{
		Endpoint:   ts.URL,
		Model:      "gpt-4o-mini",
		HTTPClient: ts.Client(),
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	result, err := AssureProvider(context.Background(), p)
	if err != nil {
		t.Fatalf("AssureProvider failed: %v", err)
	}

	if !result.Passed {
		t.Fatalf("expected provider assurance result to pass: %#v", result)
	}
	if result.ConfigurationDigest == "" {
		t.Fatalf("expected non-empty configuration digest")
	}
	if result.ReportedModel != "gpt-4o-mini" {
		t.Fatalf("unexpected reported model: %s", result.ReportedModel)
	}
}
