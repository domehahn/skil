package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/domehahn/skil/internal/signing"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPackageInstallAndLockWorkflow(t *testing.T) {
	temp := t.TempDir()
	archive := filepath.Join(temp, "reviewer.tgz")
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"package", "build", fixture(t, "clean-skill"), "--output", archive}); code != ExitOK {
		t.Fatalf("package failed: code=%d stderr=%s", code, errOut.String())
	}
	keyPath := filepath.Join(temp, "key.pem")
	keyID, publicKey, err := signing.GeneratePrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signaturePath := filepath.Join(temp, "package-signature.json")
	attestationPath := filepath.Join(temp, "attestation.json")
	provenancePath := filepath.Join(temp, "provenance.json")
	policyPath := filepath.Join(temp, "policy.yaml")
	commands := [][]string{
		{"package", "sign", archive, "--signing-key", keyPath, "--output", signaturePath},
		{"attest", archive, "--signing-key", keyPath, "--output", attestationPath},
		{"provenance", "create", archive, "--repository", "https://example.test/repo", "--commit", "0123456789abcdef", "--builder", "test-builder", "--signing-key", keyPath, "--output", provenancePath},
	}
	for _, args := range commands {
		out.Reset()
		errOut.Reset()
		if code := app.Run(context.Background(), args); code != ExitOK {
			t.Fatalf("%v failed: code=%d stderr=%s", args, code, errOut.String())
		}
	}
	policyData := fmt.Sprintf("version: 1\nmaximum_severity: CRITICAL\nrequire_artifact_digest: true\nrequire_signature: true\nrequire_provenance: true\nrequire_provenance_signature: true\ntrusted_signers:\n  %s: %s\ntrusted_builders: [test-builder]\ntrusted_builder_keys:\n  test-builder: [%s]\nallowed_repositories: [https://example.test/repo]\n", keyID, publicKey, keyID)
	if err := os.WriteFile(policyPath, []byte(policyData), 0o600); err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(temp, "installed")
	lockPath := filepath.Join(temp, "agent-skills.lock")
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"install", archive, "--destination", installRoot, "--lock", lockPath,
		"--policy", policyPath, "--package-signature", signaturePath, "--attestation", attestationPath, "--provenance", provenancePath}); code != ExitOK {
		t.Fatalf("install failed: code=%d stderr=%s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(installRoot, "safe-reviewer-1.0.0", "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"lock", "verify", archive, "--lock", lockPath}); code != ExitOK {
		t.Fatalf("lock verify failed: code=%d stderr=%s", code, errOut.String())
	}
}

func TestInstallHasNoUngatedPath(t *testing.T) {
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{
		"install", "missing.tgz", "--destination", t.TempDir(),
	})
	if code != ExitInput || !strings.Contains(errOut.String(), "--policy") {
		t.Fatalf("ungated install was not rejected early: code=%d stderr=%s", code, errOut.String())
	}
}

func TestFlagsAfterPositionalAndExitCodes(t *testing.T) {
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"scan", fixture(t, "clean-skill"), "--format", "json", "--static-only"}); code != ExitOK {
		t.Fatalf("code %d stderr %s", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"scan", fixture(t, "malicious-skill"), "--format", "sarif"}); code != ExitGateFail {
		t.Fatalf("expected gate failure, got %d stderr %s", code, errOut.String())
	}
}

func TestDefinitionOfDoneCommands(t *testing.T) {
	cases := [][]string{
		{"validate", fixture(t, "clean-skill")},
		{"verify", fixture(t, "capability-mismatch-skill"), "--format", "json"},
		{"eval", fixture(t, "example"), "--runtime", "mock"},
		{"attest", fixture(t, "clean-skill")},
		{"baseline", "create", fixture(t, "example")},
	}
	expected := []int{ExitOK, ExitGateFail, ExitOK, ExitOK, ExitOK}
	for i, args := range cases {
		var out, errOut bytes.Buffer
		if code := New(&out, &errOut).Run(context.Background(), args); code != expected[i] {
			t.Errorf("%v: got %d want %d stderr=%s", args, code, expected[i], errOut.String())
		}
	}
}

func TestOptionalAnalyzerArgumentsFailSafely(t *testing.T) {
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"scan", fixture(t, "clean-skill"), "--static-only", "--semantic", "--semantic-model", "x"}); code != ExitInput {
		t.Fatalf("expected conflicting mode rejection, got %d", code)
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"scan", fixture(t, "clean-skill"), "--semantic"}); code != ExitInput {
		t.Fatalf("expected missing model rejection, got %d", code)
	}
}
