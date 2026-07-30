package openssf

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
	client      *http.Client
	endpoint    string
	cachePath   string
	cacheTTL    time.Duration
	offline     bool
	mu          sync.Mutex
	cacheLoaded bool
	cache       map[string]cacheEntry
	diagnostics []skil.Diagnostic
}

func New() *Provider { return NewConfigured(Config{}) }

func NewWithClient(client *http.Client) *Provider {
	return NewConfigured(Config{HTTPClient: client})
}

func newForTest(client *http.Client, target string) *Provider {
	provider := NewConfigured(Config{HTTPClient: client})
	provider.endpoint = target
	return provider
}

func NewConfigured(config Config) *Provider {
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OpenSSF redirects are disabled") }}
	}
	ttl := config.CacheTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Provider{
		client: client, endpoint: endpoint,
		cachePath: config.CachePath, cacheTTL: ttl,
		offline: config.Offline, cache: map[string]cacheEntry{},
	}
}

func (p *Provider) ID() string { return "openssf-malicious" }

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

var maliciousPrefixes = []string{"MAL-", "GHSA-MAL-", "PYSEC-MALICIOUS"}

func isMalicious(id string) bool {
	upper := strings.ToUpper(id)
	for _, prefix := range maliciousPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func (p *Provider) Query(ctx context.Context, ecosystem, name, version string) ([]skil.Vulnerability, error) {
	if strings.TrimSpace(ecosystem) == "" || strings.TrimSpace(name) == "" || strings.TrimSpace(version) == "" {
		return nil, errors.New("OpenSSF query requires ecosystem, package, and version")
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
			p.addDiagnostic("warning", "OpenSSF offline mode used an expired cache entry for "+name+"@"+version)
			return cached, nil
		}
		return nil, fmt.Errorf("OpenSSF offline cache miss for %s@%s", name, version)
	}
	out, err := p.queryRemote(ctx, ecosystem, name, version)
	if err != nil {
		if exists {
			p.addDiagnostic("warning", "OpenSSF network lookup failed; an expired cache entry was used for "+name+"@"+version)
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
			return nil, fmt.Errorf("OpenSSF request: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, maxResponseBytes+1))
		_ = httpResponse.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read OpenSSF response: %w", readErr)
		}
		if len(body) > maxResponseBytes {
			return nil, errors.New("OpenSSF response exceeds size limit")
		}
		if httpResponse.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OpenSSF returned HTTP %d", httpResponse.StatusCode)
		}
		var decoded response
		if err := json.Unmarshal(body, &decoded); err != nil {
			return nil, fmt.Errorf("decode OpenSSF response: %w", err)
		}
		for _, item := range decoded.Vulns {
			if !isMalicious(item.ID) {
				continue
			}
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
	return nil, errors.New("OpenSSF pagination limit exceeded")
}

func recordSeverity(r record) skil.Severity {
	for _, s := range r.Severity {
		switch s.Type {
		case "CVSS_V3", "CVSS_V2":
			score := 0.0
			if _, err := fmt.Sscanf(s.Score, "%f", &score); err == nil {
				switch {
				case score >= 9.0:
					return skil.SeverityCritical
				case score >= 7.0:
					return skil.SeverityHigh
				case score >= 4.0:
					return skil.SeverityMedium
				}
			}
		}
	}
	return skil.SeverityHigh
}

func shorten(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

func cacheKey(ecosystem, name, version string) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(ecosystem)),
		strings.ToLower(strings.TrimSpace(name)),
		strings.TrimSpace(version),
	}, "\x00")
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
	p.cache[key] = cacheEntry{
		StoredAt: time.Now().UTC(),
		Results:  append([]skil.Vulnerability(nil), results...),
	}
	if p.cachePath == "" {
		return nil
	}
	parent := filepath.Dir(p.cachePath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create OpenSSF cache directory: %w", err)
	}
	temp, err := os.CreateTemp(parent, ".skil-openssf-cache-*")
	if err != nil {
		return fmt.Errorf("create OpenSSF cache: %w", err)
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
		return fmt.Errorf("replace OpenSSF cache: %w", err)
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
		return fmt.Errorf("read OpenSSF cache: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxResponseBytes {
		return errors.New("OpenSSF cache must be a regular, non-symlink file within the size limit")
	}
	data, err := os.ReadFile(p.cachePath)
	if err != nil {
		return fmt.Errorf("read OpenSSF cache: %w", err)
	}
	var document cacheDocument
	if err := json.Unmarshal(data, &document); err != nil || document.Version != 1 || document.Entries == nil {
		return errors.New("OpenSSF cache is invalid")
	}
	reencoded, err := json.Marshal(document.Entries)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(reencoded)
	if hex.EncodeToString(digest[:]) != document.SHA256 {
		return errors.New("OpenSSF cache integrity check failed")
	}
	p.cache = document.Entries
	return nil
}

func (p *Provider) addDiagnostic(level, message string) {
	p.diagnostics = append(p.diagnostics, skil.Diagnostic{
		Component: "openssf-malicious", Level: level, Message: message,
	})
}
