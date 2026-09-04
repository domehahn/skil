package tests

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/internal/registry"
)

func TestRegistryE2EGoldenFixtures(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	catalogPath := filepath.Join(tempDir, "catalog.json")

	cat, err := registry.NewFileCatalog(catalogPath)
	if err != nil {
		t.Fatal(err)
	}

	fixturesRoot := filepath.Join("fixtures", "registry")

	// 1. Index base skill kubernetes-deployer
	basePath := filepath.Join(fixturesRoot, "kubernetes-deployer")
	baseEntry, baseContent, err := registry.LoadCandidateEntry(basePath, "")
	if err != nil {
		t.Fatalf("load base entry failed: %v", err)
	}

	provider := registry.NewLocalTFIDFProvider()
	rep := registry.BuildSemanticRepresentation(baseEntry.Metadata, baseEntry.Capabilities, baseContent, registry.RepresentationFull)
	vec, _ := provider.Embed(ctx, rep)
	baseEntry.Embedding = vec

	if err := cat.Add(ctx, baseEntry); err != nil {
		t.Fatal(err)
	}

	analyzer := registry.NewDuplicateAnalyzer(cat, provider, nil, registry.DefaultAdmissionConfig())
	evaluator := registry.NewAdmissionEvaluator(registry.DefaultAdmissionConfig())

	// Test 1: exact-copy
	exactPath := filepath.Join(fixturesRoot, "exact-copy")
	exactEntry, _, _ := registry.LoadCandidateEntry(exactPath, "")
	exactEntry.ID = "exact-copy-candidate"
	exactRes, err := analyzer.AnalyzeDuplicates(ctx, exactEntry, "", 5)
	if err != nil {
		t.Fatalf("exact-copy analyze failed: %v", err)
	}
	if exactRes.Relationship != registry.RelationshipExactDuplicate {
		t.Fatalf("expected EXACT_DUPLICATE for exact-copy, got %s", exactRes.Relationship)
	}
	exactAdm := evaluator.EvaluateAdmission(ctx, exactRes)
	if exactAdm.Decision != registry.DecisionReject {
		t.Fatalf("expected REJECT for exact-copy, got %s", exactAdm.Decision)
	}

	// Test 2: subset-skill
	subsetPath := filepath.Join(fixturesRoot, "subset-skill")
	subsetEntry, _, _ := registry.LoadCandidateEntry(subsetPath, "")
	subsetEntry.ID = "subset-skill-candidate"
	subsetRes, err := analyzer.AnalyzeDuplicates(ctx, subsetEntry, "", 5)
	if err != nil {
		t.Fatalf("subset-skill analyze failed: %v", err)
	}
	if subsetRes.Relationship != registry.RelationshipSubset {
		t.Fatalf("expected SUBSET for subset-skill, got %s (reason: %s)", subsetRes.Relationship, subsetRes.Reason)
	}
	subsetAdm := evaluator.EvaluateAdmission(ctx, subsetRes)
	if subsetAdm.Decision != registry.DecisionReject {
		t.Fatalf("expected REJECT for subset-skill, got %s", subsetAdm.Decision)
	}

	// Test 3: superset-skill
	supersetPath := filepath.Join(fixturesRoot, "superset-skill")
	supersetEntry, _, _ := registry.LoadCandidateEntry(supersetPath, "")
	supersetEntry.ID = "superset-skill-candidate"
	supersetRes, err := analyzer.AnalyzeDuplicates(ctx, supersetEntry, "", 5)
	if err != nil {
		t.Fatalf("superset-skill analyze failed: %v", err)
	}
	if supersetRes.Relationship != registry.RelationshipSuperset {
		t.Fatalf("expected SUPERSET for superset-skill, got %s (reason: %s)", supersetRes.Relationship, supersetRes.Reason)
	}
	supersetAdm := evaluator.EvaluateAdmission(ctx, supersetRes)
	if supersetAdm.Decision != registry.DecisionReview {
		t.Fatalf("expected REVIEW for superset-skill, got %s", supersetAdm.Decision)
	}

	// Test 4: distinct-skill
	distinctPath := filepath.Join(fixturesRoot, "distinct-skill")
	distinctEntry, _, _ := registry.LoadCandidateEntry(distinctPath, "")
	distinctEntry.ID = "distinct-skill-candidate"
	distinctRes, err := analyzer.AnalyzeDuplicates(ctx, distinctEntry, "", 5)
	if err != nil {
		t.Fatalf("distinct-skill analyze failed: %v", err)
	}
	if distinctRes.Relationship != registry.RelationshipDistinct {
		t.Fatalf("expected DISTINCT for distinct-skill, got %s", distinctRes.Relationship)
	}
	distinctAdm := evaluator.EvaluateAdmission(ctx, distinctRes)
	if distinctAdm.Decision != registry.DecisionAccept {
		t.Fatalf("expected ACCEPT for distinct-skill, got %s", distinctAdm.Decision)
	}

	// Test 5: malicious-prompt-injection
	maliciousPath := filepath.Join(fixturesRoot, "malicious-prompt-injection")
	maliciousEntry, maliciousContent, _ := registry.LoadCandidateEntry(maliciousPath, "")
	maliciousEntry.ID = "malicious-prompt-injection-candidate"
	maliciousRes, err := analyzer.AnalyzeDuplicates(ctx, maliciousEntry, maliciousContent, 5)
	if err != nil {
		t.Fatalf("malicious analyze failed: %v", err)
	}
	maliciousAdm := evaluator.EvaluateAdmission(ctx, maliciousRes)
	if maliciousAdm.Decision == "" {
		t.Fatalf("expected valid admission decision, got empty")
	}
}
