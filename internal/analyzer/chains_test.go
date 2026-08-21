package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func chainFindingStub(ruleID string) skil.Finding {
	return skil.Finding{RuleID: ruleID, Fingerprint: "fp-" + ruleID, Location: skil.Location{File: "SKILL.md", StartLine: 1}}
}

func TestCorrelateThreatChainsFiresOnlyWhenEverySignalPresent(t *testing.T) {
	findings := []skil.Finding{
		chainFindingStub("SKIL-OBF-001"),
		chainFindingStub("SKIL-TAINT-OUTPUT-EXECUTION"),
	}
	chains := correlateThreatChains(findings, nil)
	if !hasRule(chains, "SKIL-CHAIN-INJECT-EXEC") {
		t.Fatalf("expected SKIL-CHAIN-INJECT-EXEC to fire when both signals are present: %#v", chains)
	}
	for _, chain := range chains {
		if chain.RuleID == "SKIL-CHAIN-INJECT-EXEC" {
			rules, _ := chain.Evidence["contributing_rules"].([]string)
			if len(rules) != 2 || rules[0] != "SKIL-OBF-001" || rules[1] != "SKIL-TAINT-OUTPUT-EXECUTION" {
				t.Fatalf("unexpected contributing rules evidence: %#v", chain.Evidence)
			}
		}
	}
}

func TestCorrelateThreatChainsDoesNotFireOnPartialSignal(t *testing.T) {
	// Only the hidden-instruction half of SKIL-CHAIN-INJECT-EXEC — no
	// execution-sink finding — must not fire the chain.
	findings := []skil.Finding{chainFindingStub("SKIL-OBF-001")}
	chains := correlateThreatChains(findings, nil)
	if hasRule(chains, "SKIL-CHAIN-INJECT-EXEC") {
		t.Fatalf("chain fired with only one of its two required signals: %#v", chains)
	}
	if len(chains) != 0 {
		t.Fatalf("expected no chains from a single unrelated signal: %#v", chains)
	}
}

func TestCorrelateThreatChainsSupplyChainCompromise(t *testing.T) {
	findings := []skil.Finding{
		chainFindingStub("SKIL-DEP-001"),
		chainFindingStub("SKIL-DEP-002"),
	}
	chains := correlateThreatChains(findings, nil)
	if !hasRule(chains, "SKIL-CHAIN-SUPPLY-CHAIN-COMPROMISE") {
		t.Fatalf("expected supply-chain-compromise chain: %#v", chains)
	}
}

func TestCorrelateThreatChainsDeceptiveMultiAgent(t *testing.T) {
	findings := []skil.Finding{
		chainFindingStub("SKIL-MEMORY-FALSE-REPRESENTATION"),
		chainFindingStub("SKIL-TAINT-OUTPUT-CROSS-AGENT"),
	}
	chains := correlateThreatChains(findings, nil)
	if !hasRule(chains, "SKIL-CHAIN-DECEPTIVE-MULTIAGENT") {
		t.Fatalf("expected deceptive-multiagent chain: %#v", chains)
	}
}

func TestCorrelateThreatChainsDeceptiveCredentialHarvest(t *testing.T) {
	findings := []skil.Finding{
		chainFindingStub("SKIL-UNI-002"),
		chainFindingStub("SKIL-SEC-001"),
	}
	chains := correlateThreatChains(findings, nil)
	if !hasRule(chains, "SKIL-CHAIN-DECEPTIVE-CREDENTIAL-HARVEST") {
		t.Fatalf("expected deceptive-credential-harvest chain: %#v", chains)
	}
}

func TestCorrelateThreatChainsIsDeterministicAcrossRuns(t *testing.T) {
	findings := []skil.Finding{
		chainFindingStub("SKIL-OBF-001"),
		chainFindingStub("SKIL-TAINT-EXECUTION"),
		chainFindingStub("SKIL-DEP-001"),
		chainFindingStub("SKIL-DEP-MALICIOUS"),
	}
	first := correlateThreatChains(findings, nil)
	second := correlateThreatChains(findings, nil)
	if len(first) != len(second) {
		t.Fatalf("non-deterministic chain count: %d vs %d", len(first), len(second))
	}
	for index := range first {
		if first[index].RuleID != second[index].RuleID || first[index].Fingerprint != second[index].Fingerprint {
			t.Fatalf("non-deterministic chain output at index %d: %#v vs %#v", index, first[index], second[index])
		}
	}
}

// TestScanEmitsSupplyChainCompromiseChainEndToEnd proves the wiring into
// Registry.Scan, not just the unit-level correlation function: a real
// unpinned, typosquat-named dependency parsed by the real Dependency
// analyzer produces both SKIL-DEP-001 and SKIL-DEP-002 from one entry,
// and Scan correlates them into the chain finding.
func TestScanEmitsSupplyChainCompromiseChainEndToEnd(t *testing.T) {
	artifact := artifactWith("pyproject.toml", `[project]
name = "fixture"
version = "1.0.0"
dependencies = [
  "reqeusts",
]
`)
	registry := DefaultRegistry(nil)
	result, err := registry.Scan(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(result.Findings, "SKIL-DEP-001") || !hasRule(result.Findings, "SKIL-DEP-002") {
		t.Fatalf("fixture did not produce the expected constituent findings: %#v", result.Findings)
	}
	if !hasRule(result.Findings, "SKIL-CHAIN-SUPPLY-CHAIN-COMPROMISE") {
		t.Fatalf("expected Scan to correlate the chain finding: %#v", result.Findings)
	}
}
