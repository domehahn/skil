package analyzer

import (
	"github.com/domehahn/skil/pkg/skil"
	"testing"
)

func TestMissingRequiredRuleMakesPackIncomplete(t *testing.T) {
	pack := RulePackIntegrity{ID: "core", Version: "1", Provenance: "embedded:rules/core.yaml", Rules: []RuleArtifact{{Rule: skil.Rule{ID: "R1", Title: "x", Category: "test", Severity: skil.SeverityHigh, Analysis: "static"}, Version: "1", Capability: "shell", DecisionSemantics: "block", Provenance: "embedded"}}}
	validated, err := ValidateRulePack(pack, []string{"R1", "R2"})
	if err == nil || validated.Complete {
		t.Fatalf("missing rule did not fail closed: %#v", validated)
	}
}
