package policy

import "testing"

func TestPromotionCannotJumpToEnforceWithoutEvidence(t *testing.T) {
	stage, err := Promote(PromotionShadow, PromotionEvidence{Recall: .99, FalsePositiveRate: .01, HardNegativePass: true, Deterministic: true, Monotonic: true})
	if err == nil || stage != PromotionShadow {
		t.Fatal("rule promoted without benchmark identity")
	}
	stage, err = Promote(PromotionShadow, PromotionEvidence{Recall: .99, FalsePositiveRate: .01, HardNegativePass: true, Deterministic: true, Monotonic: true, BenchmarkDigest: "sha256:b"})
	if err != nil || stage != PromotionBenchmarked {
		t.Fatalf("valid promotion rejected: %s %v", stage, err)
	}
}

func TestEnforcementRequiresVerifiedState(t *testing.T) {
	state := AssuranceEnforcementState{AuthorizationWeakened: true}
	if len(EnforcementReasons(state)) != 0 {
		t.Fatal("unverified suspicion became hard enforcement")
	}
	state.EvidenceVerified = true
	if got := EnforcementReasons(state); len(got) != 1 || got[0] != "authorization_weakened" {
		t.Fatalf("verified state not enforced: %#v", got)
	}
}
