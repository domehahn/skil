package verification

import (
	"github.com/domehahn/skil/pkg/skil"
	"testing"
)

func TestUndeclaredNetworkFails(t *testing.T) {
	result := Verify(skil.SkillContract{}, []skil.Finding{{RuleID: "SKIL-NET-001"}})
	if result.Status != skil.StatusFail || len(result.Mismatches) != 1 {
		t.Fatalf("%#v", result)
	}
}

func TestConcreteAllowlistMismatchAndOverdeclaration(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Network:  skil.NetworkCapability{Outbound: true, Hosts: []string{"api.example.com"}},
		Commands: skil.CommandCapability{Execute: true, Allow: []string{"git status"}},
	}}
	findings := []skil.Finding{
		{RuleID: "SKIL-NET-001", Evidence: map[string]any{"network_host": "evil.example"}},
		{RuleID: "SKIL-PY-002", Evidence: map[string]any{"command": "curl"}},
	}
	result := Verify(contract, findings)
	if result.Status != skil.StatusFail {
		t.Fatalf("expected allowlist mismatch: %#v", result)
	}
	if len(result.Mismatches) != 2 {
		t.Fatalf("expected host and command mismatches: %#v", result.Mismatches)
	}
}

func TestOverdeclarationWarns(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Network: skil.NetworkCapability{Outbound: true, Hosts: []string{"api.example.com"}},
	}}
	result := Verify(contract, nil)
	if result.Status != skil.StatusWarn || result.Mismatches[0].Kind != "overdeclared" {
		t.Fatalf("expected least-privilege warning: %#v", result)
	}
}

func TestDeclaredObservedCapabilityMatchIsClean(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Filesystem: skil.FilesystemCapability{Read: []string{"docs/**"}},
	}}
	result := Verify(contract, nil)
	if result.Status == skil.StatusFail {
		t.Fatalf("matching/no observed capability must not be underdeclared: %#v", result)
	}
	for _, mismatch := range result.Mismatches {
		if mismatch.Kind == "underdeclared" {
			t.Fatalf("unexpected underdeclaration: %#v", result)
		}
	}
}

func TestVerificationOutputIsNotReusedAsCapabilityEvidence(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Network: skil.NetworkCapability{Outbound: true, Hosts: []string{"api.example.com"}},
	}}
	// Simulate re-verifying a scan whose findings already contain a prior
	// overdeclared mismatch finding for the same capability (as produced by
	// Findings()). That finding must not be mistaken for fresh evidence
	// that the capability was actually observed.
	prior := Verify(contract, nil)
	priorFindings := Findings(prior, skil.Artifact{})
	result := Verify(contract, priorFindings)
	if result.Status != skil.StatusWarn {
		t.Fatalf("re-verification must still report overdeclaration, not treat prior output as evidence: %#v", result)
	}
	if result.Observed.NetworkOutbound {
		t.Fatalf("verification output must not be inferred as observed capability: %#v", result)
	}
	if len(result.Mismatches) != 1 || result.Mismatches[0].Kind != "overdeclared" {
		t.Fatalf("expected a single overdeclared mismatch: %#v", result.Mismatches)
	}
}

func TestCapabilityEvidenceDrivesObservationForNewAnalyzers(t *testing.T) {
	result := Verify(skil.SkillContract{}, []skil.Finding{{
		RuleID:   "SKIL-PY-REFLECT-EXEC",
		Evidence: map[string]any{"capability": "commands.execute", "command": "system"},
	}})
	if result.Status != skil.StatusFail || !result.Observed.CommandsExecute {
		t.Fatalf("capability evidence was not enforced: %#v", result)
	}
}
