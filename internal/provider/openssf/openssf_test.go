package openssf

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestQueryFiltersOnlyMalicious(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.Header.Get("User-Agent") == "" {
			t.Errorf("unexpected request")
		}
		body := `{"vulns":[
			{"id":"GHSA-xxxx-xxxx-xxxx","summary":"a CVE (not malicious)"},
			{"id":"MAL-2023-1","summary":"malicious package","aliases":["PYSEC-2023-1"]},
			{"id":"PYSEC-2023-1","summary":"already seen via aliases"}
		]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	items, err := newForTest(client, "https://openssf.test/query").Query(context.Background(), "PyPI", "demo", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 malicious-only result, got %d: %#v", len(items), items)
	}
	if items[0].ID != "MAL-2023-1" {
		t.Fatalf("expected MAL-2023-1, got %s", items[0].ID)
	}
	if len(items[0].Aliases) != 1 || items[0].Aliases[0] != "PYSEC-2023-1" {
		t.Fatalf("aliases not retained: %#v", items[0])
	}
}

func TestQueryRejectsBadStatus(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	if _, err := newForTest(client, "https://openssf.test/query").Query(context.Background(), "npm", "x", "1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestQueryRejectsMissingFields(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"vulns":[]}`)), Header: make(http.Header)}, nil
	})}
	if _, err := newForTest(client, "https://openssf.test/query").Query(context.Background(), "", "x", "1"); err == nil {
		t.Fatal("expected error for empty ecosystem")
	}
	if _, err := newForTest(client, "https://openssf.test/query").Query(context.Background(), "npm", "", "1"); err == nil {
		t.Fatal("expected error for empty package name")
	}
}

func TestIsMaliciousDetection(t *testing.T) {
	tests := []struct {
		id     string
		expect bool
	}{
		{"MAL-2023-1", true},
		{"MAL-2024-100", true},
		{"GHSA-mal-1234", true},
		{"PYSEC-malicious-2023-1", true},
		{"GHSA-xxxx-xxxx-xxxx", false},
		{"CVE-2023-1234", false},
		{"PYSEC-2023-1", false},
		{"", false},
	}
	for _, tc := range tests {
		got := isMalicious(tc.id)
		if got != tc.expect {
			t.Errorf("isMalicious(%q) = %v, want %v", tc.id, got, tc.expect)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
