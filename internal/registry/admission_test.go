package registry

import (
	"context"
	"testing"
)

func TestAdmissionEvaluatorPolicyAndAllowRule(t *testing.T) {
	config := DefaultAdmissionConfig()
	config.AllowRules = []AllowRule{
		{
			Candidate: "k8s-prod-deployer",
			RelatedTo: "kubernetes-deployer",
			Reason:    "Approved hardened production specialization",
		},
	}

	evaluator := NewAdmissionEvaluator(config)
	ctx := context.Background()

	// 1. REJECT exact duplicate
	resReject := evaluator.EvaluateAdmission(ctx, DuplicateAnalysisResult{
		Candidate:    Metadata{Name: "exact-copy"},
		Relationship: RelationshipExactDuplicate,
		Reason:       "Exact content hash match.",
	})
	if resReject.Decision != DecisionReject {
		t.Fatalf("expected REJECT for EXACT_DUPLICATE, got %s", resReject.Decision)
	}

	// 2. REVIEW for SUPERSET
	resReview := evaluator.EvaluateAdmission(ctx, DuplicateAnalysisResult{
		Candidate:    Metadata{Name: "k8s-extended"},
		Relationship: RelationshipSuperset,
		Reason:       "Candidate extends existing skill.",
		Matches: []DuplicateMatch{
			{Entry: CatalogEntry{Name: "kubernetes-deployer"}},
		},
	})
	if resReview.Decision != DecisionReview {
		t.Fatalf("expected REVIEW for SUPERSET, got %s", resReview.Decision)
	}

	// 3. ALLOWED BY RULE
	resAllowed := evaluator.EvaluateAdmission(ctx, DuplicateAnalysisResult{
		Candidate:    Metadata{Name: "k8s-prod-deployer"},
		Relationship: RelationshipSubset,
		Reason:       "Subset of kubernetes-deployer",
		Matches: []DuplicateMatch{
			{Entry: CatalogEntry{Name: "kubernetes-deployer"}},
		},
	})
	if resAllowed.Decision != DecisionAcceptWithWarning {
		t.Fatalf("expected ACCEPT_WITH_WARNING for allowed rule, got %s", resAllowed.Decision)
	}
	if resAllowed.AllowedBy == nil || resAllowed.AllowedBy.Reason != "Approved hardened production specialization" {
		t.Fatalf("expected AllowedBy rule match, got %#v", resAllowed.AllowedBy)
	}
}
