package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContinuousCheckRequiresPolicyAndState(t *testing.T) {
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"continuous", "check", "skill"})
	if code != ExitInput || !strings.Contains(errOut.String(), "--policy and --state") {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
}

func TestContinuousCheckPersistsState(t *testing.T) {
	root := fixture(t, "clean-skill")
	state := filepath.Join(t.TempDir(), "assurance-state.json")
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nmaximum_severity: CRITICAL\nrequire_artifact_digest: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"continuous", "check", root, "--policy", policyPath, "--state", state, "--static-only", "--format", "json"})
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "artifact_digest") || !strings.Contains(out.String(), "policy") {
		t.Fatalf("unexpected state/report: %s / %s", data, out.String())
	}
}
