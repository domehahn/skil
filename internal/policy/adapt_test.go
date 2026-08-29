package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdaptPolicyFromTraceSynthesizesTightPolicy(t *testing.T) {
	tempDir := t.TempDir()

	tracePath := filepath.Join(tempDir, "trace.json")
	traceData := `{"observed_capabilities": ["filesystem.read"], "used_tools": ["Read"]}`
	if err := os.WriteFile(tracePath, []byte(traceData), 0644); err != nil {
		t.Fatal(err)
	}

	outPolicyPath := filepath.Join(tempDir, "policy.yaml")
	pol, yamlStr, err := AdaptPolicyFromTrace(tracePath, outPolicyPath)
	if err != nil {
		t.Fatalf("AdaptPolicyFromTrace failed: %v", err)
	}

	if len(pol.AllowedCapabilities) != 1 || pol.AllowedCapabilities[0] != "filesystem.read" {
		t.Fatalf("expected allowed capability filesystem.read, got %v", pol.AllowedCapabilities)
	}

	if yamlStr == "" {
		t.Fatalf("expected non-empty yaml policy string")
	}

	if _, err := os.Stat(outPolicyPath); os.IsNotExist(err) {
		t.Fatalf("expected adapted policy file to exist at %s", outPolicyPath)
	}
}
