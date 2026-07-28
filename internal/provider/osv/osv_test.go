package osv

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
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
