package registry

import (
	"context"
	"fmt"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func BenchmarkCanonicalFingerprint(b *testing.B) {
	files := []skil.File{
		{Path: "SKILL.md", Data: []byte("# Kubernetes Deployer\nDeploy applications into Kubernetes clusters.")},
		{Path: "skil.yaml", Data: []byte("domain: [kubernetes]\ncapabilities: [deploy, rollback]")},
		{Path: "scripts/deploy.sh", Data: []byte("#!/bin/bash\nkubectl apply -f deployment.yaml")},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CanonicalFingerprint("", files)
	}
}

func BenchmarkLocalTFIDFEmbedding(b *testing.B) {
	provider := NewLocalTFIDFProvider()
	ctx := context.Background()
	text := "Deploy applications and Helm charts into Kubernetes clusters with automated status checks and canary rollouts."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.Embed(ctx, text)
	}
}

func BenchmarkCatalogSearchSimilar(b *testing.B) {
	ctx := context.Background()
	cat, _ := NewFileCatalog("")
	provider := NewLocalTFIDFProvider()

	// Seed 100 synthetic skills into catalog
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("skill-%d", i)
		entry := CatalogEntry{
			ID:          name,
			Name:        name,
			Version:     "1.0.0",
			Fingerprint: FingerprintInfo{Value: fmt.Sprintf("sha256:hash-%d", i)},
			Metadata:    Metadata{Name: name, Description: fmt.Sprintf("Synthetic skill %d for benchmark testing.", i)},
			Capabilities: CapabilityFingerprint{
				Domain:  []string{"kubernetes"},
				Actions: []string{"deploy", "scan"},
			},
		}
		rep := BuildSemanticRepresentation(entry.Metadata, entry.Capabilities, "", RepresentationFull)
		vec, _ := provider.Embed(ctx, rep)
		entry.Embedding = vec
		_ = cat.Add(ctx, entry)
	}

	cand := CatalogEntry{
		Metadata: Metadata{Name: "candidate-skill", Description: "Deploy applications into k8s."},
		Capabilities: CapabilityFingerprint{
			Domain:  []string{"kubernetes"},
			Actions: []string{"deploy"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cat.SearchSimilar(ctx, cand, 5, provider)
	}
}
