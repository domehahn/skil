package assurance

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestEvaluateProviderInputBudgetCountsFullWirePayload(t *testing.T) {
	budget := ProviderInputBudget{
		MaxSerializedBytes: 500,
		MaxEstimatedTokens: 200,
	}
	// Raw artifact content is only 100 bytes (under 500), but system prompt + schema + metadata push wire size over 500 bytes.
	acc, err := EvaluateProviderInputBudget(
		budget,
		make([]byte, 200), // system instructions
		make([]byte, 100), // prompt template
		make([]byte, 100), // raw artifact content
		make([]byte, 80),  // metadata
		make([]byte, 120), // output schema
		nil,
	)
	if err == nil || !acc.Exceeded {
		t.Fatalf("expected provider input budget to fail when full serialized wire payload (%d) exceeds 500 bytes", acc.TotalSerializedBytes)
	}
	if acc.TotalSerializedBytes != 600 {
		t.Fatalf("expected 600 total serialized bytes, got %d", acc.TotalSerializedBytes)
	}
}

func TestResourceAccountingSelfProtectionDowngradesComplete(t *testing.T) {
	rep := &skil.AssuranceReport{
		Outcome: skil.OutcomeComplete,
		Proof: skil.AssuranceOutcomeProof{
			Outcome:  skil.OutcomeComplete,
			Evidence: []string{"sha256:init"},
		},
	}
	ra := ResourceAccounting{
		FilesDiscovered:        10,
		FilesLoaded:            9,
		SelfProtectionTriggers: []string{"yaml alias expansion limit exceeded in SKILL.md"},
	}
	ra.Finalize(rep, "sha256:subject")
	if rep.Outcome == skil.OutcomeComplete {
		t.Fatal("self-protection budget trigger must prevent COMPLETE assurance")
	}
	if err := rep.Proof.Validate(); err != nil {
		t.Fatalf("expected valid partial proof after self-protection trigger, got %v", err)
	}
}
