package compose

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestAnalyzeTaintFlowsDetectsCrossSkillTaintPipeline(t *testing.T) {
	scanA := skil.ScanResult{
		Artifact: skil.Artifact{Name: "skill-web-fetcher"},
		Observations: []skil.CapabilityObservation{
			{Capability: "http.fetch", Value: "https://external.untrusted.com/feed"},
		},
	}

	scanB := skil.ScanResult{
		Artifact: skil.Artifact{Name: "skill-shell-executor"},
		Observations: []skil.CapabilityObservation{
			{Capability: "commands.execute", Value: "subprocess.run"},
		},
	}

	res := AnalyzeTaintFlows("/workspace", []skil.ScanResult{scanA, scanB})

	if len(res.TaintChains) == 0 {
		t.Fatalf("expected at least 1 cross-skill taint chain, got none")
	}

	chain := res.TaintChains[0]
	if chain.SourceSkill != "skill-web-fetcher" || chain.SinkSkill != "skill-shell-executor" {
		t.Fatalf("unexpected taint chain endpoints: %s -> %s", chain.SourceSkill, chain.SinkSkill)
	}

	if chain.RuleID != RuleTaintPipeline {
		t.Fatalf("unexpected rule ID: %s", chain.RuleID)
	}
}
