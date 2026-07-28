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

func TestCapabilityEvidenceDrivesObservationForNewAnalyzers(t *testing.T) {
	result := Verify(skil.SkillContract{}, []skil.Finding{{
		RuleID:   "SKIL-PY-REFLECT-EXEC",
		Evidence: map[string]any{"capability": "commands.execute", "command": "system"},
	}})
	if result.Status != skil.StatusFail || !result.Observed.CommandsExecute {
		t.Fatalf("capability evidence was not enforced: %#v", result)
	}
}
