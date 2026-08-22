package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestHTTPSReferenceFetcherRejectsNonHTTPS(t *testing.T) {
	fetcher := httpsReferenceFetcher()
	if _, err := fetcher(context.Background(), "http://example.test/x", 1<<20); err == nil ||
		!strings.Contains(err.Error(), "https") {
		t.Fatalf("expected an https-required error, got %v", err)
	}
}

func TestHTTPSReferenceFetcherRejectsCredentialsInURL(t *testing.T) {
	fetcher := httpsReferenceFetcher()
	if _, err := fetcher(context.Background(), "https://user:pass@example.test/x", 1<<20); err == nil ||
		!strings.Contains(err.Error(), "credentials") {
		t.Fatalf("expected a credentials-rejected error, got %v", err)
	}
}

func TestHTTPSReferenceFetcherRejectsPrivateHost(t *testing.T) {
	fetcher := httpsReferenceFetcher()
	if _, err := fetcher(context.Background(), "https://127.0.0.1/x", 1<<20); err == nil ||
		!strings.Contains(err.Error(), "prohibited") {
		t.Fatalf("expected a private-address-rejected error, got %v", err)
	}
}

func TestHTTPSReferenceFetcherRejectsZeroRemainingBudget(t *testing.T) {
	fetcher := httpsReferenceFetcher()
	if _, err := fetcher(context.Background(), "https://example.test/x", 0); err == nil ||
		!strings.Contains(err.Error(), "budget") {
		t.Fatalf("expected a budget-exhausted error, got %v", err)
	}
}

func TestReferenceSuffixPreservesRecognizedExtension(t *testing.T) {
	if got := referenceSuffix("/path/to/helper.py"); got != ".py" {
		t.Fatalf("expected .py, got %q", got)
	}
	if got := referenceSuffix("/path/with/no/extension"); got != ".ref" {
		t.Fatalf("expected fallback .ref, got %q", got)
	}
}

func TestScanWithoutTransitiveFlagOmitsReferencesField(t *testing.T) {
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{
		"scan", fixture(t, "clean-skill"), "--static-only", "--format", "json",
	})
	if code != ExitOK {
		t.Fatalf("unexpected code=%d stderr=%s", code, errOut.String())
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("parse scan JSON output: %v\n%s", err, out.String())
	}
	if _, present := result["references"]; present {
		t.Fatalf("expected no 'references' field without --transitive: %s", out.String())
	}
}

// TestScanWithTransitiveFlagOnReferenceFreeFixtureMakesNoNetworkCall proves
// --transitive is safe on an ordinary fixture with no external references
// at all: the traversal must terminate immediately without ever reaching
// the network (a fixture whose content has no https:// reference simply
// yields an empty graph).
func TestScanWithTransitiveFlagOnReferenceFreeFixtureMakesNoNetworkCall(t *testing.T) {
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{
		"scan", fixture(t, "clean-skill"), "--static-only", "--transitive", "--format", "json",
	})
	if code != ExitOK {
		t.Fatalf("unexpected code=%d stderr=%s", code, errOut.String())
	}
	var result struct {
		References []struct{} `json:"references"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("parse scan JSON output: %v\n%s", err, out.String())
	}
	if len(result.References) != 0 {
		t.Fatalf("expected an empty reference graph for a fixture with no external references: %#v", result.References)
	}
}

func TestScanRejectsTransitiveDepthTypeErrorsSafely(t *testing.T) {
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{
		"scan", fixture(t, "clean-skill"), "--static-only", "--transitive-depth", "not-a-number",
	})
	if code != ExitInput {
		t.Fatalf("expected ExitInput for a malformed --transitive-depth, got %d stderr=%s", code, errOut.String())
	}
}
