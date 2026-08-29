package policy

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestSynthesizeFromScanGeneratesLeastPrivilegePolicy(t *testing.T) {
	scan := skil.ScanResult{
		Artifact: skil.Artifact{Name: "clean-skill", Digest: "abc"},
		Maximum:  skil.SeverityLow,
		Coverage: map[string]skil.CoverageState{
			"pattern":  skil.CoverageCompleted,
			"semantic": skil.CoverageCompleted,
		},
		Observations: []skil.CapabilityObservation{
			{Capability: "permission.filesystem.write", Value: "/tmp/out"},
		},
	}

	pol, yamlStr, err := SynthesizeFromScan(scan, true)
	if err != nil {
		t.Fatalf("SynthesizeFromScan failed: %v", err)
	}

	if pol.MaximumSeverity != "LOW" {
		t.Fatalf("expected MaximumSeverity LOW, got %s", pol.MaximumSeverity)
	}

	if pol.AgentExecution == nil || *pol.AgentExecution.AllowShellHooks || *pol.AgentExecution.AllowPermissionBypass {
		t.Fatalf("expected AgentExecution allow_shell_hooks and allow_permission_bypass to be false")
	}

	if !pol.RequireCompleteTransitiveClosure {
		t.Fatalf("expected strict mode to set RequireCompleteTransitiveClosure")
	}

	if yamlStr == "" {
		t.Fatalf("expected non-empty YAML output")
	}
}
