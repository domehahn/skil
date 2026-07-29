package osv

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

func TestQueryAndPagination(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.Header.Get("User-Agent") == "" {
			t.Errorf("unexpected request")
		}
		body := `{"vulns":[{"id":"GHSA-2","summary":"also bad"}]}`
		if calls == 1 {
			body = `{"vulns":[{"id":"GHSA-1","aliases":["GO-TEST-1"],"summary":"bad","affected":[{"ecosystem_specific":{"severity":"CRITICAL"}}]}],"next_page_token":"next"}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	items, err := newForTest(client, "https://osv.test/query").Query(context.Background(), "PyPI", "demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Severity != "CRITICAL" || calls != 2 {
		t.Fatalf("%#v calls=%d", items, calls)
	}
	if len(items[0].Aliases) != 1 || items[0].Aliases[0] != "GO-TEST-1" {
		t.Fatalf("aliases were not retained: %#v", items[0])
	}
}

func TestBatchCacheAndOfflineFallback(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "osv-cache.json")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `{"results":[{"vulns":[{"id":"OSV-1","summary":"bad"}]},{"vulns":[]}]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	provider := NewConfigured(Config{HTTPClient: client, CachePath: cachePath, CacheTTL: time.Hour})
	provider.batchEndpoint = "https://osv.test/querybatch"
	queries := []skil.VulnerabilityQuery{
		{Ecosystem: "npm", Package: "a", Version: "1.0.0"},
		{Ecosystem: "PyPI", Package: "b", Version: "2.0.0"},
	}
	results, err := provider.QueryBatch(context.Background(), queries)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || len(results[0]) != 1 || results[0][0].ID != "OSV-1" {
		t.Fatalf("unexpected results: %#v", results)
	}
	offline := NewConfigured(Config{CachePath: cachePath, CacheTTL: time.Hour, Offline: true})
	cached, err := offline.QueryBatch(context.Background(), queries)
	if err != nil {
		t.Fatal(err)
	}
	if len(cached[0]) != 1 || cached[0][0].ID != "OSV-1" {
		t.Fatalf("offline cache did not reproduce results: %#v", cached)
	}
}

func TestQueryRejectsBadStatus(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	if _, err := newForTest(client, "https://osv.test/query").Query(context.Background(), "npm", "x", "1"); err == nil {
		t.Fatal("expected error")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
