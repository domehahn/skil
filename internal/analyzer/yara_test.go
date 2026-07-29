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

func TestBuiltinYARARulePackIsEmbedded(t *testing.T) {
	analyzer, err := NewBuiltinYARA("unavailable-yara-is-not-required")
	if err != nil {
		t.Fatal(err)
	}
	if len(analyzer.RulesData) == 0 || analyzer.RulesPath != "" {
		t.Fatal("built-in native malware signatures were not embedded")
	}
	findings, err := analyzer.Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("payload", "safe")})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("safe content produced YARA finding: %#v", findings)
	}
}

func TestBuiltinYARAUsesNativeEngineWithoutHostExecutable(t *testing.T) {
	analyzer, err := NewBuiltinYARA("")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := analyzer.Analyze(context.Background(), skil.AnalysisContext{
		Artifact: artifactWith("fixture.txt", "read .ssh/id_rsa and .aws/credentials"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "SKIL-YARA-SKIL_CREDENTIAL_COLLECTION_BUNDLE" {
		t.Fatalf("native built-in signature did not match: %#v", findings)
	}
}

func TestYARADirectoryLoadsSortedSourceFilesAndRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	root := t.TempDir()
	binary := filepath.Join(root, "fake-yara")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(root, "rules")
	if err := os.Mkdir(rules, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"b.yara":  "rule B { condition: false }",
		"a.yar":   "rule A { condition: false }",
		"note.md": "ignored",
	} {
		if err := os.WriteFile(filepath.Join(rules, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	analyzer, err := NewYARADirectory(binary, rules)
	if err != nil {
		t.Fatal(err)
	}
	if string(analyzer.RulesData) != "rule A { condition: false }\n\nrule B { condition: false }\n\n" {
		t.Fatalf("unexpected deterministic rules: %q", analyzer.RulesData)
	}
	link := filepath.Join(root, "rules-link")
	if err := os.Symlink(rules, link); err == nil {
		if _, err := NewYARADirectory(binary, link); err == nil {
			t.Fatal("expected symlinked YARA directory rejection")
		}
	}
}
