package evidence

import "testing"

func completeV2Inputs() AttestationInputsV2 {
	return AttestationInputsV2{SubjectIdentity: "sha256:s", ClosureDigest: "sha256:c", PolicyDigest: "sha256:p", EvidenceGraphDigest: "sha256:e", ObserverDigest: "sha256:o", AnalysisPlanDigest: "sha256:a", WorkLedgerDigest: "sha256:w", BudgetPolicyDigest: "sha256:b", AnalysisCompleteness: "FULL", ResolutionCompleteness: "EXACT", DiscoveryCompleteness: "COMPLETE", AuthorizationConstraintDigest: "sha256:ac", EffectiveAuthorityDigest: "sha256:ea", BehavioralSuiteDigest: "sha256:be", RuntimeEvidenceDigest: "sha256:r", LossOfControlDigest: "sha256:l", FinalDecision: "ALLOW"}
}
func TestAttestationV2InvalidatesBehavioralAndAuthorityDrift(t *testing.T) {
	a, err := NewAttestationV2(completeV2Inputs())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(); err != nil {
		t.Fatal(err)
	}
	a.Inputs.EffectiveAuthorityDigest = "sha256:widened"
	if a.Verify() == nil {
		t.Fatal("widened authority preserved attestation")
	}
	b, _ := NewAttestationV2(completeV2Inputs())
	b.Inputs.BehavioralSuiteDigest = "sha256:stale"
	if b.Verify() == nil {
		t.Fatal("behavioral drift preserved attestation")
	}
}
