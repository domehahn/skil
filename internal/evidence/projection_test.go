package evidence

import (
	"github.com/domehahn/skil/pkg/skil"
	"testing"
)

func TestSecurityProjectionSurvivesLossyRepresentations(t *testing.T) {
	p, err := ProjectFinding(skil.Finding{ID: "f1", RuleID: "r1", Category: "runtime_violation", Severity: skil.SeverityHigh, Confidence: 1, Location: skil.Location{File: "skill.py", StartLine: 2}}, "sha256:artifact", skil.EvidenceVerified, []string{"runtime:canary"})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProjectionPreserved([]SecurityProjection{p}, []SecurityProjection{p}); err != nil {
		t.Fatal(err)
	}
	lost := p
	lost.Verification = skil.EvidenceInferred
	if VerifyProjectionPreserved([]SecurityProjection{p}, []SecurityProjection{lost}) == nil {
		t.Fatal("VERIFIED to INFERRED collision was not detected")
	}
}

func TestResponseProjectionProof(t *testing.T) {
	raw := []byte(`{"findings":[{"rule_id":"SKIL-SEM-SECURITY"}]}`)
	findings := []skil.Finding{{ID: "f1", RuleID: "SKIL-SEM-SECURITY", Severity: skil.SeverityHigh}}
	proof, err := BuildResponseProjectionProof(raw, map[string]any{"findings": findings}, findings, nil, false, true)
	if err != nil || !proof.Complete {
		t.Fatalf("expected valid complete proof, got complete=%v err=%v", proof.Complete, err)
	}

	// Unmapped critical signal must fail closed
	if _, err := BuildResponseProjectionProof(raw, map[string]any{}, nil, []string{"unmapped_exfiltration_signal"}, false, true); err == nil {
		t.Fatal("expected error when critical signals are unmapped")
	}
	// Truncated response must fail closed
	if _, err := BuildResponseProjectionProof(raw, map[string]any{}, nil, nil, true, true); err == nil {
		t.Fatal("expected error when response is truncated")
	}
}
