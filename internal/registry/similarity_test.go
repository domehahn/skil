package registry

import (
	"context"
	"testing"
)

func TestNameMetadataSimilaritySlugAlias(t *testing.T) {
	cand := Metadata{Name: "k8s-deployer", Title: "Kubernetes Deployer"}
	exist := Metadata{Name: "kubernetes-deployer", Title: "Kubernetes Deployer"}

	res := NameMetadataSimilarity(cand, exist)
	if res.OverallScore < 0.85 {
		t.Fatalf("expected high name similarity between k8s-deployer and kubernetes-deployer, got %f", res.OverallScore)
	}
}

func TestLocalTFIDFProviderCosineSimilarity(t *testing.T) {
	provider := NewLocalTFIDFProvider()
	ctx := context.Background()

	vec1, err := provider.Embed(ctx, "deploy helm chart into kubernetes cluster")
	if err != nil {
		t.Fatalf("Embed 1 failed: %v", err)
	}
	vec2, err := provider.Embed(ctx, "deploy application with helm to k8s cluster")
	if err != nil {
		t.Fatalf("Embed 2 failed: %v", err)
	}
	vec3, err := provider.Embed(ctx, "scan terraform files for security vulnerabilities")
	if err != nil {
		t.Fatalf("Embed 3 failed: %v", err)
	}

	sim12 := provider.Similarity(vec1, vec2)
	sim13 := provider.Similarity(vec1, vec3)

	if sim12 <= sim13 {
		t.Fatalf("expected k8s deployment texts to be more similar (%f) than terraform scan (%f)", sim12, sim13)
	}
}
