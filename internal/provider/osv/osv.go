// Package osv implements opt-in vulnerability lookup through the OSV API.
package osv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

const endpoint = "https://api.osv.dev/v1/query"
const maxResponseBytes = 8 << 20

type Config struct {
	HTTPClient *http.Client
	CachePath  string
	CacheTTL   time.Duration
	Offline    bool
}

type Provider struct {
	client        *http.Client
	endpoint      string
	batchEndpoint string
	cachePath     string
	cacheTTL      time.Duration
	offline       bool
	mu            sync.Mutex
	cacheLoaded   bool
	cache         map[string]cacheEntry
	diagnostics   []skil.Diagnostic
}

func New() *Provider {
	return NewConfigured(Config{})
}
func NewWithClient(client *http.Client) *Provider {
	return NewConfigured(Config{HTTPClient: client})
}
func newForTest(client *http.Client, target string) *Provider {
	provider := NewConfigured(Config{HTTPClient: client})
	provider.endpoint = target
	provider.batchEndpoint = target + "batch"
	return provider
}
func (p *Provider) ID() string { return "osv.dev" }

func NewConfigured(config Config) *Provider {
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OSV redirects are disabled") }}
	}
	ttl := config.CacheTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Provider{client: client, endpoint: endpoint,
		batchEndpoint: "https://api.osv.dev/v1/querybatch", cachePath: config.CachePath,
		cacheTTL: ttl, offline: config.Offline, cache: map[string]cacheEntry{}}
}

type cacheEntry struct {
	StoredAt time.Time            `json:"stored_at"`
	Results  []skil.Vulnerability `json:"results"`
}
type cacheDocument struct {
	Version int                   `json:"version"`
	Entries map[string]cacheEntry `json:"entries"`
	SHA256  string                `json:"entries_sha256"`
}

func (p *Provider) Diagnostics() []skil.Diagnostic {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]skil.Diagnostic(nil), p.diagnostics...)
}

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
	key := cacheKey(ecosystem, name, version)
	cached, fresh, exists, err := p.cached(key)
	if err != nil {
		return nil, err
	}
	if exists && fresh {
		return cached, nil
	}
	if p.offline {
		if exists {
			p.addDiagnostic("warning", "OSV offline mode used an expired cache entry for "+name+"@"+version)
			return cached, nil
		}
		return nil, fmt.Errorf("OSV offline cache miss for %s@%s", name, version)
	}
	out, err := p.queryRemote(ctx, ecosystem, name, version)
	if err != nil {
		if exists {
			p.addDiagnostic("warning", "OSV network lookup failed; an expired cache entry was used for "+name+"@"+version)
			return cached, nil
		}
		return nil, err
	}
	if err := p.store(key, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Provider) queryRemote(ctx context.Context, ecosystem, name, version string) ([]skil.Vulnerability, error) {
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

func cacheKey(ecosystem, name, version string) string {
	return strings.Join([]string{strings.ToLower(strings.TrimSpace(ecosystem)), strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(version)}, "\x00")
}

func (p *Provider) cached(key string) ([]skil.Vulnerability, bool, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.loadCacheLocked(); err != nil {
		return nil, false, false, err
	}
	entry, ok := p.cache[key]
	if !ok {
		return nil, false, false, nil
	}
	results := append([]skil.Vulnerability(nil), entry.Results...)
	return results, time.Since(entry.StoredAt) <= p.cacheTTL, true, nil
}

func (p *Provider) store(key string, results []skil.Vulnerability) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.loadCacheLocked(); err != nil {
		return err
	}
	p.cache[key] = cacheEntry{StoredAt: time.Now().UTC(), Results: append([]skil.Vulnerability(nil), results...)}
	if p.cachePath == "" {
		return nil
	}
	parent := filepath.Dir(p.cachePath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create OSV cache directory: %w", err)
	}
	temp, err := os.CreateTemp(parent, ".skil-osv-cache-*")
	if err != nil {
		return fmt.Errorf("create OSV cache: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	encodedEntries, err := json.Marshal(p.cache)
	if err != nil {
		_ = temp.Close()
		return err
	}
	digest := sha256.Sum256(encodedEntries)
	encoder := json.NewEncoder(temp)
	err = encoder.Encode(cacheDocument{Version: 1, Entries: p.cache, SHA256: hex.EncodeToString(digest[:])})
	closeErr := temp.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	if err := os.Rename(tempPath, p.cachePath); err != nil {
		return fmt.Errorf("replace OSV cache: %w", err)
	}
	return nil
}

func (p *Provider) loadCacheLocked() error {
	if p.cacheLoaded {
		return nil
	}
	p.cacheLoaded = true
	if p.cachePath == "" {
		return nil
	}
	info, err := os.Lstat(p.cachePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read OSV cache: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxResponseBytes {
		return errors.New("OSV cache must be a regular, non-symlink file within the size limit")
	}
	data, err := os.ReadFile(p.cachePath)
	if err != nil {
		return fmt.Errorf("read OSV cache: %w", err)
	}
	var document cacheDocument
	if err := json.Unmarshal(data, &document); err != nil || document.Version != 1 || document.Entries == nil {
		return errors.New("OSV cache is invalid")
	}
	encodedEntries, err := json.Marshal(document.Entries)
	if err != nil {
		return errors.New("OSV cache is invalid")
	}
	digest := sha256.Sum256(encodedEntries)
	if document.SHA256 == "" || document.SHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("OSV cache integrity check failed")
	}
	now := time.Now().UTC()
	for key, entry := range document.Entries {
		if key == "" || entry.StoredAt.IsZero() || entry.StoredAt.After(now.Add(5*time.Minute)) {
			return errors.New("OSV cache contains an invalid entry")
		}
	}
	p.cache = document.Entries
	return nil
}

func (p *Provider) addDiagnostic(level, message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.diagnostics = append(p.diagnostics, skil.Diagnostic{Component: p.ID(), Level: level, Message: message})
}

func (p *Provider) QueryBatch(ctx context.Context, queries []skil.VulnerabilityQuery) ([][]skil.Vulnerability, error) {
	if len(queries) > 1_000 {
		return nil, errors.New("OSV batch query limit exceeded")
	}
	out := make([][]skil.Vulnerability, len(queries))
	// The provider still uses the batch endpoint for misses, while cache hits
	// and degraded fallback remain query-specific and auditable.
	var misses []int
	for index, item := range queries {
		if strings.TrimSpace(item.Ecosystem) == "" || strings.TrimSpace(item.Package) == "" || strings.TrimSpace(item.Version) == "" {
			return nil, errors.New("OSV batch query requires ecosystem, package, and version")
		}
		cached, fresh, exists, err := p.cached(cacheKey(item.Ecosystem, item.Package, item.Version))
		if err != nil {
			return nil, err
		}
		if exists && fresh {
			out[index] = cached
		} else {
			misses = append(misses, index)
		}
	}
	if len(misses) == 0 {
		return out, nil
	}
	if p.offline {
		for _, index := range misses {
			item := queries[index]
			cached, _, exists, err := p.cached(cacheKey(item.Ecosystem, item.Package, item.Version))
			if err != nil {
				return nil, err
			}
			if !exists {
				return nil, fmt.Errorf("OSV offline cache miss for %s@%s", item.Package, item.Version)
			}
			out[index] = cached
			p.addDiagnostic("warning", "OSV offline mode used an expired cache entry for "+item.Package+"@"+item.Version)
		}
		return out, nil
	}
	for start := 0; start < len(misses); start += 100 {
		end := min(start+100, len(misses))
		indices := misses[start:end]
		if err := p.queryBatchChunk(ctx, queries, indices, out); err != nil {
			for _, index := range indices {
				item := queries[index]
				cached, _, exists, cacheErr := p.cached(cacheKey(item.Ecosystem, item.Package, item.Version))
				if cacheErr != nil || !exists {
					return nil, err
				}
				out[index] = cached
				p.addDiagnostic("warning", "OSV batch lookup failed; an expired cache entry was used for "+item.Package+"@"+item.Version)
			}
		}
	}
	return out, nil
}

func (p *Provider) queryBatchChunk(ctx context.Context, queries []skil.VulnerabilityQuery, indices []int, out [][]skil.Vulnerability) error {
	requestQueries := make([]query, 0, len(indices))
	for _, index := range indices {
		item := queries[index]
		requestQueries = append(requestQueries, query{Version: item.Version, Package: pkg{Name: item.Package, Ecosystem: item.Ecosystem}})
	}
	payload, err := json.Marshal(struct {
		Queries []query `json:"queries"`
	}{Queries: requestQueries})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.batchEndpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "skil/"+skil.Version)
	httpResponse, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("OSV batch request: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, maxResponseBytes+1))
	_ = httpResponse.Body.Close()
	if readErr != nil {
		return readErr
	}
	if len(body) > maxResponseBytes || httpResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("OSV batch returned invalid HTTP response %d", httpResponse.StatusCode)
	}
	var decoded struct {
		Results []response `json:"results"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || len(decoded.Results) != len(indices) {
		return errors.New("OSV batch returned an invalid result set")
	}
	for position, index := range indices {
		item := queries[index]
		out[index] = normalizeRecords(item.Package, item.Version, decoded.Results[position].Vulns)
		if err := p.store(cacheKey(item.Ecosystem, item.Package, item.Version), out[index]); err != nil {
			return err
		}
	}
	return nil
}

func normalizeRecords(name, version string, records []record) []skil.Vulnerability {
	seen := map[string]bool{}
	var out []skil.Vulnerability
	for _, item := range records {
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
		out = append(out, skil.Vulnerability{Package: name, Version: version, ID: item.ID,
			Summary: summary, Severity: recordSeverity(item), Aliases: append([]string(nil), item.Aliases...)})
	}
	return out
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
