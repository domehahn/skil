package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func writeExplanationFixture(t *testing.T, status skil.Status, verdict skil.Verdict) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan.json")
	data, err := json.Marshal(skil.ScanResult{
		SchemaVersion: "1.0.0", Artifact: skil.Artifact{Name: "fixture", Digest: "abc123"},
		Status: status, Verdict: verdict, Findings: []skil.Finding{{RuleID: "SKIL-TEST", Severity: skil.SeverityHigh, Title: "Test finding", Description: "review this", Location: skil.Location{File: "SKILL.md", StartLine: 4}}},
		Coverage: map[string]skil.CoverageState{"static": skil.CoverageCompleted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExplainTerminalAndJSON(t *testing.T) {
	path := writeExplanationFixture(t, skil.StatusFail, skil.VerdictBlock)
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"explain", path}); code != ExitGateFail {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "SKIL EXPLANATION") || !strings.Contains(out.String(), "SKIL-TEST") {
		t.Fatalf("unexpected terminal output: %s", out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"explain", path, "--format", "json"}); code != ExitGateFail {
		t.Fatalf("json code=%d stderr=%s", code, errOut.String())
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["authoritative"] != true {
		t.Fatalf("expected authoritative explanation, got %#v", result["authoritative"])
	}
}

func TestExplainRejectsMalformedScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"status":"PASS"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{"explain", path})
	if code != ExitInput || !strings.Contains(errOut.String(), "artifact.digest") {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
}
