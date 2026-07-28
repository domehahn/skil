// Package osv implements opt-in vulnerability lookup through the OSV API.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

const endpoint = "https://api.osv.dev/v1/query"
const maxResponseBytes = 8 << 20

type Provider struct {
	client   *http.Client
	endpoint string
}

func New() *Provider {
	return &Provider{client: &http.Client{Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OSV redirects are disabled") }}, endpoint: endpoint}
}
func NewWithClient(client *http.Client) *Provider {
	if client == nil {
		return New()
	}
	return &Provider{client: client, endpoint: endpoint}
}
func newForTest(client *http.Client, target string) *Provider {
	return &Provider{client: client, endpoint: target}
}
func (p *Provider) ID() string { return "osv.dev" }

type query struct {
	Version   string `json:"version"`
	Package   pkg    `json:"package"`
	PageToken string `json:"page_token,omitempty"`
}
type pkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type response struct {
	Vulns         []record `json:"vulns"`
	NextPageToken string   `json:"next_page_token"`
}
type record struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
	Affected         []struct {
		EcosystemSpecific map[string]any `json:"ecosystem_specific"`
	} `json:"affected"`
}

func (p *Provider) Query(ctx context.Context, ecosystem, name, version string) ([]skil.Vulnerability, error) {
	if strings.TrimSpace(ecosystem) == "" || strings.TrimSpace(name) == "" || strings.TrimSpace(version) == "" {
		return nil, errors.New("OSV query requires ecosystem, package, and version")
	}
	pageToken := ""
	seen := map[string]bool{}
	var out []skil.Vulnerability
	for page := 0; page < 10; page++ {
		payload, err := json.Marshal(query{Version: version, Package: pkg{Name: name, Ecosystem: ecosystem}, PageToken: pageToken})
		if err != nil {
			return nil, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "skil/"+skil.Version)
		httpResponse, err := p.client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("OSV request: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, maxResponseBytes+1))
		_ = httpResponse.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read OSV response: %w", readErr)
		}
		if len(body) > maxResponseBytes {
			return nil, errors.New("OSV response exceeds size limit")
		}
		if httpResponse.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OSV returned HTTP %d", httpResponse.StatusCode)
		}
		var decoded response
		if err := json.Unmarshal(body, &decoded); err != nil {
			return nil, fmt.Errorf("decode OSV response: %w", err)
		}
		for _, item := range decoded.Vulns {
			duplicate := seen[item.ID]
			for _, alias := range item.Aliases {
				duplicate = duplicate || seen[alias]
			}
			if item.ID == "" || duplicate {
				continue
			}
			seen[item.ID] = true
			for _, alias := range item.Aliases {
				seen[alias] = true
			}
			summary := item.Summary
			if summary == "" {
				summary = shorten(item.Details, 240)
			}
			out = append(out, skil.Vulnerability{
				Package: name, Version: version, ID: item.ID, Summary: summary,
				Severity: recordSeverity(item), Aliases: append([]string(nil), item.Aliases...),
			})
		}
		if decoded.NextPageToken == "" {
			return out, nil
		}
		pageToken = decoded.NextPageToken
	}
	return nil, errors.New("OSV pagination limit exceeded")
}

func recordSeverity(item record) skil.Severity {
	for _, affected := range item.Affected {
		if severity := severityValue(affected.EcosystemSpecific["severity"]); severity != "" {
			return severity
		}
	}
	if severity := severityValue(item.DatabaseSpecific["severity"]); severity != "" {
		return severity
	}
	for _, value := range item.Severity {
		upper := strings.ToUpper(value.Score)
		for _, candidate := range []skil.Severity{skil.SeverityCritical, skil.SeverityHigh, skil.SeverityMedium, skil.SeverityLow} {
			if strings.Contains(upper, string(candidate)) {
				return candidate
			}
		}
	}
	return skil.SeverityHigh
}

func severityValue(value any) skil.Severity {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	switch strings.ToUpper(text) {
	case "CRITICAL":
		return skil.SeverityCritical
	case "HIGH":
		return skil.SeverityHigh
	case "MODERATE", "MEDIUM":
		return skil.SeverityMedium
	case "LOW":
		return skil.SeverityLow
	default:
		return ""
	}
}

func shorten(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}
