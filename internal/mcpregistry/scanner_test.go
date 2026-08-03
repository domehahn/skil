package mcpregistry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

const cleanServer = `{
  "$schema":"https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name":"io.github.example/weather",
  "description":"Weather data",
  "version":"1.2.3",
  "repository":{"url":"https://github.com/example/weather","source":"github"},
  "packages":[{"registryType":"npm","identifier":"@example/weather","version":"1.2.3"}],
  "remotes":[{"type":"streamable-http","url":"https://weather.example/mcp"}]
}`

func TestScanCleanPublisherRecord(t *testing.T) {
	report, err := Scan("server.json", []byte(cleanServer), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Summary.Passed || len(report.Records) != 1 || report.Records[0].RecordSHA256 == "" {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestScanDetectsRegistryPostureFailures(t *testing.T) {
	document := `{
      "metadata":{"count":2},
      "servers":[{
        "server":{
          "$schema":"https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
          "name":"io.github.owner/server",
          "description":"unsafe",
          "version":"latest",
          "repository":{"url":"http://github.com/other/server","source":"github"},
          "packages":[
            {"registryType":"npm","identifier":"pkg","version":"^1.0.0","fileSha256":"bad"},
            {"registryType":"mcpb","identifier":"https://example.test/server.mcpb"}
          ],
          "remotes":[{"type":"sse","url":"http://example.test/mcp"}]
        },
        "_meta":{"io.modelcontextprotocol.registry/official":{"status":"deprecated","isLatest":false}}
      }]
    }`
	report, err := Scan("registry.json", []byte(document), Options{Official: true, LatestEndpoint: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"MCP-REG-002", "MCP-REG-005", "MCP-REG-006", "MCP-REG-007", "MCP-REG-008", "MCP-REG-009", "MCP-REG-010", "MCP-REG-012"} {
		if !hasFinding(report.Findings, code) {
			t.Errorf("missing %s in %#v", code, report.Findings)
		}
	}
}

func TestReviewedClosureAndBaselineAreEnforced(t *testing.T) {
	digest := strings.Repeat("a", 64)
	server := strings.Replace(cleanServer,
		`{"registryType":"npm","identifier":"@example/weather","version":"1.2.3"}`,
		`{"registryType":"mcpb","identifier":"https://example.test/weather.mcpb","fileSha256":"`+digest+`"}`, 1)
	report, err := Scan("server.json", []byte(server), Options{
		ReviewedClosure:      map[string]string{"https://example.test/weather.mcpb": strings.Repeat("b", 64)},
		BaselineRepositories: map[string]string{"io.github.example/weather": "https://github.com/previous/weather"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(report.Findings, "MCP-REG-011") || !hasFinding(report.Findings, "MCP-REG-014") {
		t.Fatalf("missing closure or ownership finding: %#v", report.Findings)
	}
}

func TestCanonicalRecordHashIgnoresJSONFormatting(t *testing.T) {
	first, err := Scan("one", []byte(cleanServer), Options{})
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.ReplaceAll(strings.ReplaceAll(cleanServer, "\n", ""), "  ", "")
	second, err := Scan("two", []byte(compact), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Records[0].RecordSHA256 != second.Records[0].RecordSHA256 {
		t.Fatalf("canonical hashes differ: %s != %s", first.Records[0].RecordSHA256, second.Records[0].RecordSHA256)
	}
}

func TestDuplicateJSONKeysAreRejected(t *testing.T) {
	if _, err := Scan("duplicate.json", []byte(`{"name":"one","name":"two"}`), Options{}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key was not rejected: %v", err)
	}
}

func TestLatestConsistencyAndDuplicateVersions(t *testing.T) {
	document := `{"metadata":{"count":2},"servers":[
      {"server":{"$schema":"x","name":"io.github.example/weather","description":"x","version":"1.0.0","repository":{"url":"https://github.com/example/weather"},"remotes":[{"type":"sse","url":"https://example.test/mcp"}]},"_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":false}}},
      {"server":{"$schema":"x","name":"io.github.example/weather","description":"x","version":"1.0.0","repository":{"url":"https://github.com/example/weather"},"remotes":[{"type":"sse","url":"https://example.test/mcp"}]},"_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":false}}}
    ]}`
	report, err := Scan("registry.json", []byte(document), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(report.Findings, "MCP-REG-016") || !hasFinding(report.Findings, "MCP-REG-017") {
		t.Fatalf("missing version consistency findings: %#v", report.Findings)
	}
}

func TestLatestMustBeHighestSemanticVersion(t *testing.T) {
	document := strings.ReplaceAll(`{"metadata":{"count":2},"servers":[
      {"server":SERVER_ONE,"_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":true}}},
      {"server":SERVER_TWO,"_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":false}}}
    ]}`, "SERVER_ONE", strings.Replace(cleanServer, `"version":"1.2.3"`, `"version":"1.2.3"`, 1))
	document = strings.Replace(document, "SERVER_TWO", strings.Replace(cleanServer, `"version":"1.2.3"`, `"version":"2.0.0"`, 1), 1)
	report, err := Scan("registry.json", []byte(document), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(report.Findings, "MCP-REG-019") {
		t.Fatalf("missing highest-version finding: %#v", report.Findings)
	}
}

func TestUnofficialSchemaIsRejected(t *testing.T) {
	report, err := Scan("server.json", []byte(strings.Replace(cleanServer, "https://static.modelcontextprotocol.io", "https://example.test", 1)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(report.Findings, "MCP-REG-018") {
		t.Fatalf("missing schema finding: %#v", report.Findings)
	}
}

func TestFetchOfficialUsesV01LatestEndpoint(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != OfficialBaseURL+"/v0.1/servers/io.github.example%2Fweather/versions/latest" {
			t.Fatalf("unexpected URL: %s", request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(cleanServer)), Header: make(http.Header)}, nil
	})
	data, source, latest, err := FetchOfficial(context.Background(), "io.github.example/weather", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || source == "" || !latest {
		t.Fatalf("unexpected fetch result: source=%q latest=%t", source, latest)
	}
}

func TestFetchOfficialPaginatesRegistry(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		body := `{"metadata":{},"servers":[{"server":` + cleanServer + `}]}`
		if requests == 1 {
			if request.URL.Query().Get("cursor") != "" {
				t.Fatalf("unexpected first cursor: %s", request.URL)
			}
			body = `{"metadata":{"nextCursor":"page two"},"servers":[{"server":` + cleanServer + `}]}`
		} else if request.URL.Query().Get("cursor") != "page two" {
			t.Fatalf("unexpected second cursor: %s", request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	data, source, latest, err := FetchOfficial(context.Background(), "", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || source != OfficialBaseURL+"/v0.1/servers" || latest {
		t.Fatalf("unexpected pagination result: requests=%d source=%q latest=%t", requests, source, latest)
	}
	var document struct {
		Servers []json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(data, &document); err != nil || len(document.Servers) != 2 {
		t.Fatalf("invalid aggregated response: err=%v data=%s", err, data)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func hasFinding(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
