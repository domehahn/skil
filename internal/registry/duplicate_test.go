package registry

import (
	"context"
	"testing"
)

func TestDuplicateAnalyzerRelationshipClassification(t *testing.T) {
	ctx := context.Background()
	catalog, err := NewFileCatalog("")
	if err != nil {
		t.Fatal(err)
	}

	existing := CatalogEntry{
		ID:   "kubernetes-deployer",
		Name: "kubernetes-deployer",
		Fingerprint: FingerprintInfo{
			Value: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
		Metadata: Metadata{
			Name:        "kubernetes-deployer",
			Description: "Deploy applications into Kubernetes clusters using kubectl and helm.",
		},
		Capabilities: CapabilityFingerprint{
			Domain:      []string{"kubernetes"},
			Actions:     []string{"deploy", "rollback", "canary", "health-check"},
			Tools:       []string{"kubectl", "helm"},
			Resources:   []string{"deployment", "service"},
			Permissions: []string{"cluster-write"},
		},
	}

	if err := catalog.Add(ctx, existing); err != nil {
		t.Fatal(err)
	}

	da := NewDuplicateAnalyzer(catalog, NewLocalTFIDFProvider(), nil, DefaultAdmissionConfig())

	// 1. Exact Duplicate
	exactCand := existing
	exactCand.ID = "candidate-exact-copy"
	resExact, err := da.AnalyzeDuplicates(ctx, exactCand, "", 5)
	if err != nil {
		t.Fatalf("AnalyzeDuplicates exact failed: %v", err)
	}
	if resExact.Relationship != RelationshipExactDuplicate {
		t.Fatalf("expected EXACT_DUPLICATE, got %s", resExact.Relationship)
	}

	// 2. Subset
	subsetCand := CatalogEntry{
		ID:   "k8s-simple-deploy",
		Name: "k8s-simple-deploy",
		Fingerprint: FingerprintInfo{
			Value: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		},
		Metadata: Metadata{
			Name:        "k8s-simple-deploy",
			Description: "Simple deployment tool for kubernetes.",
		},
		Capabilities: CapabilityFingerprint{
			Domain:    []string{"kubernetes"},
			Actions:   []string{"deploy", "rollback"},
			Tools:     []string{"kubectl"},
			Resources: []string{"deployment"},
		},
	}
	resSubset, err := da.AnalyzeDuplicates(ctx, subsetCand, "", 5)
	if err != nil {
		t.Fatalf("AnalyzeDuplicates subset failed: %v", err)
	}
	if resSubset.Relationship != RelationshipSubset {
		t.Fatalf("expected SUBSET, got %s (reason: %s)", resSubset.Relationship, resSubset.Reason)
	}

	// 3. Superset
	supersetCand := CatalogEntry{
		ID:   "kubernetes-advanced-deployer",
		Name: "kubernetes-advanced-deployer",
		Fingerprint: FingerprintInfo{
			Value: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		},
		Metadata: Metadata{
			Name:        "kubernetes-advanced-deployer",
			Description: "Advanced deployment tool for kubernetes with automated rollback and canary.",
		},
		Capabilities: CapabilityFingerprint{
			Domain:      []string{"kubernetes"},
			Actions:     []string{"deploy", "rollback", "canary", "health-check", "policy-validation", "auto-scale"},
			Tools:       []string{"kubectl", "helm", "trivy"},
			Resources:   []string{"deployment", "service", "ingress", "hpa"},
			Permissions: []string{"cluster-write", "cluster-read"},
		},
	}
	resSuperset, err := da.AnalyzeDuplicates(ctx, supersetCand, "", 5)
	if err != nil {
		t.Fatalf("AnalyzeDuplicates superset failed: %v", err)
	}
	if resSuperset.Relationship != RelationshipSuperset {
		t.Fatalf("expected SUPERSET, got %s (reason: %s)", resSuperset.Relationship, resSuperset.Reason)
	}
}
