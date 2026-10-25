// Package engine exposes composable scan orchestration for applications and
// third-party analyzers. The CLI is only one consumer of this API.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/pkg/skil"
)

// Cache stores only complete, digest-bound scan results. Implementations must
// treat keys as opaque and may evict entries at any time.
type Cache interface {
	Load(key string) (skil.ScanResult, bool)
	Store(key string, result skil.ScanResult)
}

// MemoryCache is a bounded-lifetime in-process cache suitable for CI jobs and
// embedding applications. It intentionally has no persistence or network
// behavior.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]skil.ScanResult
}

func NewMemoryCache() *MemoryCache { return &MemoryCache{entries: map[string]skil.ScanResult{}} }

func (c *MemoryCache) Load(key string) (skil.ScanResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, ok := c.entries[key]
	if !ok {
		return skil.ScanResult{}, false
	}
	return cloneResult(result)
}

func (c *MemoryCache) Store(key string, result skil.ScanResult) {
	if c == nil || key == "" || !cacheable(result) {
		return
	}
	copy, ok := cloneResult(result)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]skil.ScanResult{}
	}
	c.entries[key] = copy
}

type Registry struct {
	inner *analyzer.Registry
	cache Cache
}

// New creates a registry with all deterministic built-in analyzers.
func New(vulnerabilities skil.VulnerabilityProvider) *Registry {
	return &Registry{inner: analyzer.DefaultRegistry(vulnerabilities)}
}

// NewWithCache enables opt-in incremental reuse. Cache identity includes the
// artifact subject digest, contract, domain filter, and analyzer metadata.
// Existing callers should continue using New when caching is not desired.
func NewWithCache(vulnerabilities skil.VulnerabilityProvider, cache Cache) *Registry {
	return &Registry{inner: analyzer.DefaultRegistry(vulnerabilities), cache: cache}
}

// Register adds an external analyzer. Analyzer IDs must be globally unique.
func (r *Registry) Register(item skil.Analyzer) error { return r.inner.Register(item) }

func (r *Registry) Analyzers() []skil.AnalyzerMetadata { return r.inner.Metadata() }

func (r *Registry) Scan(ctx context.Context, input skil.AnalysisContext) (skil.ScanResult, error) {
	key := ""
	if r.cache != nil {
		key = CacheKey(input, r.inner.Metadata())
		if cached, ok := r.cache.Load(key); ok && cacheable(cached) {
			return cached, nil
		}
	}
	result, err := r.inner.Scan(ctx, input)
	if err == nil && r.cache != nil {
		r.cache.Store(key, result)
	}
	return result, err
}

func Rules() []skil.Rule { return analyzer.BuiltinRules() }

// CacheKey returns the deterministic identity for one analysis configuration.
// It deliberately excludes source paths and timestamps: only immutable content
// identity and analysis configuration may authorize reuse.
func CacheKey(input skil.AnalysisContext, metadata []skil.AnalyzerMetadata) string {
	filter := append([]string(nil), input.DomainFilter...)
	sort.Strings(filter)
	metadata = append([]skil.AnalyzerMetadata(nil), metadata...)
	sort.Slice(metadata, func(i, j int) bool { return metadata[i].ID < metadata[j].ID })
	value := struct {
		ArtifactDigest string                  `json:"artifact_digest"`
		Contract       *skil.SkillContract     `json:"contract,omitempty"`
		DomainFilter   []string                `json:"domain_filter,omitempty"`
		Analyzers      []skil.AnalyzerMetadata `json:"analyzers"`
	}{input.Artifact.SubjectDigest(), input.Contract, filter, metadata}
	data, err := json.Marshal(value)
	if err != nil || value.ArtifactDigest == "" {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func cacheable(result skil.ScanResult) bool {
	if result.Artifact.SubjectDigest() == "" || result.Status == skil.StatusError || len(result.Budget.Exceeded) > 0 || result.Completeness.Failed > 0 {
		return false
	}
	for _, state := range result.Coverage {
		if state == skil.CoverageDegraded {
			return false
		}
	}
	return true
}

func cloneResult(result skil.ScanResult) (skil.ScanResult, bool) {
	data, err := json.Marshal(result)
	if err != nil {
		return skil.ScanResult{}, false
	}
	var copy skil.ScanResult
	if err := json.Unmarshal(data, &copy); err != nil {
		return skil.ScanResult{}, false
	}
	return copy, true
}
