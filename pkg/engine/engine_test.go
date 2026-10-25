package engine

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestCacheKeyChangesWithArtifactAndConfiguration(t *testing.T) {
	input := skil.AnalysisContext{Artifact: skil.Artifact{Digest: "a"}, DomainFilter: []string{"z", "a"}}
	metadata := []skil.AnalyzerMetadata{{ID: "test", Version: "1"}}
	first := CacheKey(input, metadata)
	if first == "" {
		t.Fatal("expected cache key")
	}
	input.Artifact.Digest = "b"
	if first == CacheKey(input, metadata) {
		t.Fatal("artifact digest did not change cache key")
	}
	input.Artifact.Digest = "a"
	input.DomainFilter = []string{"a", "z"}
	if first != CacheKey(input, metadata) {
		t.Fatal("domain ordering changed cache key")
	}
}

func TestMemoryCacheReusesOnlyCompleteResults(t *testing.T) {
	cache := NewMemoryCache()
	complete := skil.ScanResult{Artifact: skil.Artifact{Digest: "a"}, Status: skil.StatusPass, Coverage: map[string]skil.CoverageState{"static": skil.CoverageCompleted}}
	cache.Store("complete", complete)
	if _, ok := cache.Load("complete"); !ok {
		t.Fatal("complete result was not cached")
	}
	incomplete := complete
	incomplete.Coverage = map[string]skil.CoverageState{"static": skil.CoverageDegraded}
	cache.Store("incomplete", incomplete)
	if _, ok := cache.Load("incomplete"); ok {
		t.Fatal("degraded result was cached")
	}
}

func TestRegistryUsesOptInCache(t *testing.T) {
	cache := NewMemoryCache()
	registry := NewWithCache(nil, cache)
	input := skil.AnalysisContext{Artifact: skil.Artifact{Name: "test", Digest: "cache-artifact", Files: []skil.File{{Path: "SKILL.md", Data: []byte("A safe review skill.")}}}}
	first, err := registry.Scan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.Scan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Artifact.Digest != second.Artifact.Digest || len(second.Inspection) == 0 {
		t.Fatalf("unexpected cached result: %#v", second)
	}
}
