package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestYARAMatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "fake-yara")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'Malware_Test %s\\n' \"$5\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(dir, "rules.yar")
	if err := os.WriteFile(rules, []byte("rule Malware_Test { condition: true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	analyzer, err := NewYARA(binary, rules)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := analyzer.Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("payload", "bad")})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "SKIL-YARA-MALWARE_TEST" {
		t.Fatalf("%#v", findings)
	}
}

func TestYARARejectsBinaryRules(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.yar")
	if err := os.WriteFile(rules, []byte{0, 1, 2}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewYARA("missing-yara", rules); err == nil {
		t.Fatal("expected rejection")
	}
}
