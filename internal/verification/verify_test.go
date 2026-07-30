package verification

import (
	"github.com/domehahn/skil/pkg/skil"
	"testing"
)

func TestUndeclaredNetworkFails(t *testing.T) {
	result := Verify(skil.SkillContract{}, []skil.Finding{{RuleID: "SKIL-NET-001"}}, nil)
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
	result := Verify(contract, findings, nil)
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
	result := Verify(contract, nil, nil)
	if result.Status != skil.StatusWarn || result.Mismatches[0].Kind != "overdeclared" {
		t.Fatalf("expected least-privilege warning: %#v", result)
	}
}

func TestDeclaredObservedCapabilityMatchIsClean(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Filesystem: skil.FilesystemCapability{Read: []string{"docs/**"}},
	}}
	result := Verify(contract, nil, nil)
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
	prior := Verify(contract, nil, nil)
	priorFindings := Findings(prior, skil.Artifact{})
	result := Verify(contract, priorFindings, nil)
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
	}}, nil)
	if result.Status != skil.StatusFail || !result.Observed.CommandsExecute {
		t.Fatalf("capability evidence was not enforced: %#v", result)
	}
}

func TestSafeCapabilityUseWithoutFindingIsNotOverdeclared(t *testing.T) {
	// A safe, allowlisted use of a declared capability (e.g. an argv-only
	// subprocess call) legitimately produces no Finding. Verification must
	// still see it as observed via the independent CapabilityObservation
	// channel, or it wrongly reports the capability as overdeclared —
	// this is the v5 blind-holdout "H35" regression: dead code aside, safe
	// declared-capability usage that emits no Finding was being reported as
	// overdeclared because observation was previously coupled to Finding
	// presence.
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Commands: skil.CommandCapability{Execute: true, Allow: []string{"git"}},
	}}
	observations := []skil.CapabilityObservation{
		{Capability: "commands.execute", Value: "git", Analyzer: "builtin.python-ast"},
	}
	result := Verify(contract, nil, observations)
	for _, mismatch := range result.Mismatches {
		if mismatch.Kind == "overdeclared" {
			t.Fatalf("safely observed capability use must not be reported as overdeclared: %#v", result.Mismatches)
		}
	}
	if !result.Observed.CommandsExecute {
		t.Fatalf("expected commands.execute to be observed from CapabilityObservation alone: %#v", result.Observed)
	}
}

func TestDeclaredFilesystemReadWithObservedUseIsNotOverdeclared(t *testing.T) {
	// LP4 parity: a declared read-only capability that the skill actually
	// exercises must not be flagged overdeclared merely because reading a
	// file (unlike writing one) produces no Finding.
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Filesystem: skil.FilesystemCapability{Read: []string{"docs/**"}},
	}}
	observations := []skil.CapabilityObservation{
		{Capability: "filesystem.read", Value: "docs/readme.txt", Analyzer: "builtin.python-ast"},
	}
	result := Verify(contract, nil, observations)
	for _, mismatch := range result.Mismatches {
		if mismatch.Kind == "overdeclared" {
			t.Fatalf("observed filesystem read use must not be overdeclared: %#v", result.Mismatches)
		}
	}
	if !result.Observed.FilesystemRead {
		t.Fatalf("expected filesystem.read to be observed: %#v", result.Observed)
	}
}

func TestDeclaredFilesystemReadNeverExercisedIsOverdeclared(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Filesystem: skil.FilesystemCapability{Read: []string{"docs/**"}},
	}}
	result := Verify(contract, nil, nil)
	found := false
	for _, mismatch := range result.Mismatches {
		if mismatch.Kind == "overdeclared" && mismatch.Capability == "filesystem.read" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an unexercised declared filesystem.read to be overdeclared: %#v", result.Mismatches)
	}
}

func TestDeclaredEnvironmentReadWithObservedUseIsNotOverdeclared(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Environment: skil.EnvironmentCapability{Read: []string{"API_TOKEN"}},
	}}
	observations := []skil.CapabilityObservation{
		{Capability: "environment.read", Value: "API_TOKEN", Analyzer: "builtin.python-ast"},
	}
	result := Verify(contract, nil, observations)
	for _, mismatch := range result.Mismatches {
		if mismatch.Kind == "overdeclared" {
			t.Fatalf("observed environment read use must not be overdeclared: %#v", result.Mismatches)
		}
	}
	if !result.Observed.EnvironmentRead {
		t.Fatalf("expected environment.read to be observed: %#v", result.Observed)
	}
}

func TestDeclaredEnvironmentReadNeverExercisedIsOverdeclared(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Environment: skil.EnvironmentCapability{Read: []string{"API_TOKEN"}},
	}}
	result := Verify(contract, nil, nil)
	found := false
	for _, mismatch := range result.Mismatches {
		if mismatch.Kind == "overdeclared" && mismatch.Capability == "environment.read" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an unexercised declared environment.read to be overdeclared: %#v", result.Mismatches)
	}
}
