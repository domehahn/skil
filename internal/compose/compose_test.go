package compose

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func obs(capability, value string) skil.CapabilityObservation {
	return skil.CapabilityObservation{Capability: capability, Value: value}
}

func scanWith(name string, observations ...skil.CapabilityObservation) skil.ScanResult {
	return skil.ScanResult{Artifact: skil.Artifact{Name: name}, Observations: observations}
}

func TestAnalyzeDetectsToxicFlowAcrossTwoSkills(t *testing.T) {
	writer := scanWith("credential-writer",
		obs("secrets.read", ""),
		obs("filesystem.write", "/tmp/shared-cache.json"))
	reader := scanWith("network-forwarder",
		obs("filesystem.read", "/tmp/shared-cache.json"),
		obs("network.outbound", "https://example.test/collect"))
	result := Analyze("test", []skil.ScanResult{writer, reader})
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly one composite finding, got %#v", result.Findings)
	}
	finding := result.Findings[0]
	if finding.RuleID != RuleToxicFlow {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, RuleToxicFlow)
	}
	if finding.Skills[0] != "credential-writer" || finding.Skills[1] != "network-forwarder" {
		t.Fatalf("Skills = %v, want [credential-writer network-forwarder]", finding.Skills)
	}
	if finding.Resource != "/tmp/shared-cache.json" {
		t.Fatalf("Resource = %q, want /tmp/shared-cache.json", finding.Resource)
	}
	if finding.Severity != skil.SeverityCritical {
		t.Fatalf("Severity = %q, want CRITICAL", finding.Severity)
	}
}

func TestAnalyzeSingleSkillNeverProducesAFinding(t *testing.T) {
	// The exact same capabilities and shared-looking resource, but all in
	// one skill: composition requires at least two skills to compose.
	solo := scanWith("solo",
		obs("secrets.read", ""),
		obs("filesystem.write", "/tmp/shared-cache.json"),
		obs("filesystem.read", "/tmp/shared-cache.json"),
		obs("network.outbound", "https://example.test"))
	result := Analyze("test", []skil.ScanResult{solo})
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for a single skill, got %#v", result.Findings)
	}
}

func TestAnalyzeNoSharedResourceProducesNoFinding(t *testing.T) {
	writer := scanWith("credential-writer", obs("secrets.read", ""), obs("filesystem.write", "/tmp/a.json"))
	reader := scanWith("network-forwarder", obs("filesystem.read", "/tmp/b.json"), obs("network.outbound", ""))
	result := Analyze("test", []skil.ScanResult{writer, reader})
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings when the resources don't match, got %#v", result.Findings)
	}
}

func TestAnalyzeSharedResourceWithoutCredentialAccessProducesNoFinding(t *testing.T) {
	writer := scanWith("plain-writer", obs("filesystem.write", "/tmp/shared.json")) // no secrets.read/environment.read
	reader := scanWith("network-forwarder", obs("filesystem.read", "/tmp/shared.json"), obs("network.outbound", ""))
	result := Analyze("test", []skil.ScanResult{writer, reader})
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings without credential access on the writer side, got %#v", result.Findings)
	}
}

func TestAnalyzeSharedResourceWithoutNetworkEgressProducesNoFinding(t *testing.T) {
	writer := scanWith("credential-writer", obs("secrets.read", ""), obs("filesystem.write", "/tmp/shared.json"))
	reader := scanWith("local-reader", obs("filesystem.read", "/tmp/shared.json")) // no network.outbound
	result := Analyze("test", []skil.ScanResult{writer, reader})
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings without network egress on the reader side, got %#v", result.Findings)
	}
}

func TestAnalyzeSameSkillWritingAndReadingIsNotComposition(t *testing.T) {
	// A single skill that both writes and reads the same resource and
	// also has network egress must not flag itself as a "cross-skill"
	// finding against itself.
	self := scanWith("self-contained",
		obs("secrets.read", ""),
		obs("filesystem.write", "/tmp/shared.json"),
		obs("filesystem.read", "/tmp/shared.json"),
		obs("network.outbound", ""))
	other := scanWith("unrelated") // present to satisfy the >=2-skills gate
	result := Analyze("test", []skil.ScanResult{self, other})
	if len(result.Findings) != 0 {
		t.Fatalf("a skill must not be flagged as a toxic flow with itself, got %#v", result.Findings)
	}
}

func TestAnalyzeDeduplicatesRepeatedObservationsOfTheSameResource(t *testing.T) {
	writer := scanWith("credential-writer",
		obs("secrets.read", ""),
		obs("filesystem.write", "/tmp/shared.json"),
		obs("filesystem.write", "/tmp/shared.json")) // observed twice, e.g. two call sites
	reader := scanWith("network-forwarder",
		obs("filesystem.read", "/tmp/shared.json"),
		obs("network.outbound", ""))
	result := Analyze("test", []skil.ScanResult{writer, reader})
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly one deduplicated finding, got %d: %#v", len(result.Findings), result.Findings)
	}
}

func TestAnalyzeThreeSkillChainProducesOneFindingPerLinkedPair(t *testing.T) {
	a := scanWith("a", obs("secrets.read", ""), obs("filesystem.write", "/tmp/x"))
	b := scanWith("b", obs("filesystem.read", "/tmp/x"), obs("network.outbound", ""))
	c := scanWith("c") // unrelated third skill, no shared resource or relevant capabilities
	result := Analyze("test", []skil.ScanResult{a, b, c})
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly one finding (a->b), got %#v", result.Findings)
	}
	if result.Skills[2] != "c" {
		t.Fatalf("expected all three skill names recorded on the result regardless of involvement: %v", result.Skills)
	}
}
