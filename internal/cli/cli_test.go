package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/domehahn/skil/internal/policy"
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
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"update", archive, "--destination", installRoot, "--lock", lockPath,
		"--policy", policyPath, "--package-signature", signaturePath, "--attestation", attestationPath, "--provenance", provenancePath}); code != ExitOK {
		t.Fatalf("update failed: code=%d stderr=%s", code, errOut.String())
	}
	tampered := filepath.Join(installRoot, "safe-reviewer-1.0.0", "unexpected.txt")
	if err := os.WriteFile(tampered, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"uninstall", "safe-reviewer", "--destination", installRoot, "--lock", lockPath}); code != ExitInput ||
		!strings.Contains(errOut.String(), "digest mismatch") {
		t.Fatalf("tampered uninstall was not rejected: code=%d stderr=%s", code, errOut.String())
	}
	if err := os.Remove(tampered); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"uninstall", "safe-reviewer", "--destination", installRoot, "--lock", lockPath}); code != ExitOK {
		t.Fatalf("uninstall failed: code=%d stderr=%s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(installRoot, "safe-reviewer-1.0.0")); !os.IsNotExist(err) {
		t.Fatalf("uninstalled target still exists: %v", err)
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"lock", "verify", archive, "--lock", lockPath}); code != ExitInput {
		t.Fatalf("removed lock entry still verifies: code=%d stderr=%s", code, errOut.String())
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

func TestLintCommandAndStrictGate(t *testing.T) {
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"lint", fixture(t, "clean-skill"), "--format", "json"}); code != ExitOK {
		t.Fatalf("lint failed: code=%d stderr=%s", code, errOut.String())
	}
	var result struct {
		Status string `json:"status"`
		Issues []struct {
			RuleID string `json:"rule_id"`
		} `json:"issues"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "WARN" || len(result.Issues) == 0 {
		t.Fatalf("expected non-gating authoring warnings: %#v", result)
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"lint", fixture(t, "clean-skill"), "--strict"}); code != ExitGateFail {
		t.Fatalf("strict lint should gate warnings: code=%d stderr=%s", code, errOut.String())
	}
}

func TestLintAllAndProfiles(t *testing.T) {
	root := t.TempDir()
	writeSkill := func(name, contract string) {
		t.Helper()
		directory := filepath.Join(root, name)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte("---\nname: "+name+"\ndescription: Collection fixture\n---\n# Fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if contract != "" {
			if err := os.WriteFile(filepath.Join(directory, "skill.yaml"), []byte(contract), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeSkill("clean", "name: clean\nversion: 1.0.0\ndescription: Collection fixture\nentrypoint: SKILL.md\nowners: [platform]\n")
	writeSkill("invalid", "")

	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{
		"lint-all", root, "--workers", "2", "--format", "json", "--profile", "portable",
	})
	if code != ExitGateFail {
		t.Fatalf("lint-all code=%d stderr=%s", code, errOut.String())
	}
	var result struct {
		Profile string `json:"profile"`
		Skills  []any  `json:"skills"`
		Failed  int    `json:"failed"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Profile != "portable" || len(result.Skills) != 2 || result.Failed != 1 {
		t.Fatalf("unexpected lint collection: %#v", result)
	}
	out.Reset()
	errOut.Reset()
	if code := New(&out, &errOut).Run(context.Background(), []string{
		"lint", fixture(t, "clean-skill"), "--profile", "unknown",
	}); code != ExitInput {
		t.Fatalf("unknown lint profile accepted: code=%d", code)
	}
}

func TestScanUsesTrustedOfflineDependencyReputation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# dependency test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("legacy-demo==1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reputationPath := filepath.Join(t.TempDir(), "reputation.json")
	reputation := `{"version":1,"packages":[{"ecosystem":"PyPI","name":"legacy-demo","abandoned":true}]}`
	if err := os.WriteFile(reputationPath, []byte(reputation), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{
		"scan", dir, "--format", "json", "--dependency-reputation", reputationPath,
	})
	if code != ExitGateFail && code != ExitOK {
		t.Fatalf("reputation scan failed: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"rule_id": "SKIL-DEP-ABANDONED"`) {
		t.Fatalf("abandoned dependency finding missing: %s", stdout.String())
	}
}

func TestScanUsesBuiltinOfflineDependencyReputation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# dependency test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("pycrypto==2.6.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{"scan", dir, "--format", "json"})
	if code != ExitOK && code != ExitGateFail {
		t.Fatalf("built-in reputation scan failed: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"rule_id": "SKIL-DEP-ABANDONED"`) ||
		!strings.Contains(stdout.String(), `"reputation": "completed"`) {
		t.Fatalf("built-in reputation coverage or finding missing: %s", stdout.String())
	}
	var result struct {
		Analysis map[string]string `json:"analysis"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Analysis["vulnerability"] != "not_requested" || result.Analysis["malware"] != "not_requested" {
		t.Fatalf("default scan activated optional providers: %#v", result.Analysis)
	}
}

func TestFullPresetIsExplicitAndDoesNotEnableSemanticAnalysis(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{
		"scan", fixture(t, "clean-skill"), "--full", "--format", "json",
	})
	if code != ExitOK {
		t.Fatalf("full scan failed: code=%d stderr=%s", code, stderr.String())
	}
	var result struct {
		Analysis map[string]string `json:"analysis"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Analysis["vulnerability"] != "completed" {
		t.Fatalf("full preset did not enable OSV coverage: %#v", result.Analysis)
	}
	if result.Analysis["semantic"] != "completed" || result.Analysis["semantic-provider"] != "not_requested" {
		t.Fatalf("full preset semantic coverage is incorrect: %#v", result.Analysis)
	}
	if result.Analysis["malware"] != "completed" {
		t.Fatalf("full preset did not request YARA coverage: %#v", result.Analysis)
	}
}

func TestFullPresetRunsBuiltinYARAWhenExecutableIsAvailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-backed fake YARA executable")
	}
	binary := filepath.Join(t.TempDir(), "fake-yara")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{
		"scan", fixture(t, "clean-skill"), "--full", "--yara-binary", binary, "--format", "json",
	})
	if code != ExitOK {
		t.Fatalf("full scan with YARA failed: code=%d stderr=%s", code, stderr.String())
	}
	var result struct {
		Analysis map[string]string `json:"analysis"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Analysis["malware"] != "completed" {
		t.Fatalf("native malware analysis did not complete under --full: %#v", result.Analysis)
	}
}

func TestCompactIsTerminalOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{
		"scan", fixture(t, "clean-skill"), "--compact", "--format", "json",
	})
	if code != ExitInput || !strings.Contains(stderr.String(), "terminal") {
		t.Fatalf("invalid compact combination accepted: code=%d stderr=%s", code, stderr.String())
	}
}

func TestDefinitionOfDoneCommands(t *testing.T) {
	cases := [][]string{
		{"lint", fixture(t, "clean-skill")},
		{"validate", fixture(t, "clean-skill")},
		{"verify", fixture(t, "capability-mismatch-skill"), "--format", "json"},
		{"eval", fixture(t, "example"), "--runtime", "mock"},
		{"attest", fixture(t, "clean-skill")},
		{"baseline", "create", fixture(t, "example")},
	}
	expected := []int{ExitOK, ExitOK, ExitGateFail, ExitOK, ExitOK, ExitOK}
	for i, args := range cases {
		var out, errOut bytes.Buffer
		if code := New(&out, &errOut).Run(context.Background(), args); code != expected[i] {
			t.Errorf("%v: got %d want %d stderr=%s", args, code, expected[i], errOut.String())
		}
	}
}

func TestAssureRequiresRealAdapterAndContainmentContract(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{
		"assure", fixture(t, "example"),
	})
	if code != ExitInput || !strings.Contains(stderr.String(), "--runtime-command") {
		t.Fatalf("assure accepted no runtime adapter: code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = New(&stdout, &stderr).Run(context.Background(), []string{
		"assure", fixture(t, "example"), "--runtime-command", "/synthetic/adapter",
	})
	if code != ExitInput || !strings.Contains(stderr.String(), "assurance requires eval containment") {
		t.Fatalf("assure accepted an eval without containment proof: code=%d stderr=%s", code, stderr.String())
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
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{
		"scan", fixture(t, "clean-skill"), "--semantic", "--semantic-model", "x",
		"--semantic-validation", "permissive",
	}); code != ExitInput || !strings.Contains(errOut.String(), "validation mode") {
		t.Fatalf("expected invalid semantic validation mode rejection, got %d stderr=%s", code, errOut.String())
	}
}

func TestEvidenceAndGateCommandsShareAnalyzerFlags(t *testing.T) {
	for _, command := range [][]string{
		{"verify", fixture(t, "clean-skill"), "--static-only", "--semantic", "--semantic-model", "x"},
		{"attest", fixture(t, "clean-skill"), "--static-only", "--semantic", "--semantic-model", "x"},
		{"policy", "check", fixture(t, "clean-skill"), "--policy", filepath.Join("..", "..", "examples", "policy.yaml"), "--static-only", "--semantic", "--semantic-model", "x"},
	} {
		var out, errOut bytes.Buffer
		code := New(&out, &errOut).Run(context.Background(), command)
		if code != ExitInput || !strings.Contains(errOut.String(), "mutually exclusive") {
			t.Fatalf("%v did not use shared analyzer validation: code=%d stderr=%s", command, code, errOut.String())
		}
	}
}

func TestValidateUniversalAuthoringManifestAndKeepPackagingStrict(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"skill.yaml": `name: reviewer
version: 1.2.3
description: Reviews changes
entrypoint: SKILL.md
license: MIT
owners: [platform]
compatible_with: [codex]
`,
		"SKILL.md":     "---\nname: reviewer\ndescription: Reviews changes\n---\n# Reviewer\n",
		"VERSION":      "1.2.3\n",
		"CHANGELOG.md": "# Changelog\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"validate", dir}); code != ExitOK {
		t.Fatalf("authoring validation failed: code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"package", "build", dir, "--output", filepath.Join(t.TempDir(), "skill.tgz")}); code != ExitInput ||
		!strings.Contains(errOut.String(), "checksums.txt") {
		t.Fatalf("package build must still require release checksums: code=%d stderr=%s", code, errOut.String())
	}
}

func TestPolicyInitCreatesValidatedPolicyWithoutOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".skil", "policy.yaml")
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"policy", "init", "--output", path}); code != ExitOK {
		t.Fatalf("policy init failed: code=%d stderr=%s", code, errOut.String())
	}
	if _, err := policy.Load(path); err != nil {
		t.Fatalf("generated policy is invalid: %v", err)
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"policy", "init", "--output", path}); code != ExitInput {
		t.Fatalf("policy init overwrote an existing file: code=%d stderr=%s", code, errOut.String())
	}
}

func TestScanOutputInsideSourceDoesNotChangeSubjectDigest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "skil.sarif")
	var firstDigest string
	for run := 0; run < 2; run++ {
		var stdout, stderr bytes.Buffer
		if code := New(&stdout, &stderr).Run(context.Background(), []string{
			"scan", dir, "--format", "sarif", "--output", output,
		}); code != ExitOK {
			t.Fatalf("scan %d failed: code=%d stderr=%s", run, code, stderr.String())
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Runs []struct {
				Properties struct {
					Skil struct {
						SubjectDigest string `json:"subject_digest"`
					} `json:"skil"`
				} `json:"properties"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		digest := document.Runs[0].Properties.Skil.SubjectDigest
		if run == 0 {
			firstDigest = digest
		} else if digest != firstDigest {
			t.Fatalf("scan output changed its own subject digest: first=%s second=%s", firstDigest, digest)
		}
	}
}

func TestSBOMAndCapabilitiesContracts(t *testing.T) {
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"sbom", fixture(t, "clean-skill")}); code != ExitOK {
		t.Fatalf("sbom failed: code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"spdxVersion": "SPDX-2.3"`) {
		t.Fatalf("unexpected SBOM: %s", out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"capabilities"}); code != ExitOK {
		t.Fatalf("capabilities failed: code=%d stderr=%s", code, errOut.String())
	}
	if strings.Contains(out.String(), `"process"`) || !strings.Contains(out.String(), `"isolated"`) {
		t.Fatalf("runtime capability is stale: %s", out.String())
	}
	var capabilities struct {
		RuntimeEnforcement bool `json:"runtime_enforcement"`
		NativeIsolation    struct {
			Available bool `json:"available"`
		} `json:"native_isolation"`
	}
	if err := json.Unmarshal(out.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities.RuntimeEnforcement != capabilities.NativeIsolation.Available {
		t.Fatalf("runtime enforcement availability is inconsistent: %s", out.String())
	}
}

func TestConformReportsASPSProfileScore(t *testing.T) {
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"conform", "--profile", "mcp", "--format", "json"}); code != ExitOK {
		t.Fatalf("conform failed: code=%d stderr=%s", code, errOut.String())
	}
	var report struct {
		Profile         string  `json:"profile"`
		TotalProperties int     `json:"total_properties"`
		Score           float64 `json:"score"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Profile != "ASPS-MCP" || report.TotalProperties != 8 {
		t.Fatalf("unexpected conform report: %s", out.String())
	}
	if report.Score <= 0 || report.Score > 1 {
		t.Fatalf("expected a score in (0,1], got %v", report.Score)
	}
}

func TestConformRejectsMissingAndUnknownProfile(t *testing.T) {
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"conform"}); code != ExitInput {
		t.Fatalf("expected missing --profile to be an input error, got code=%d", code)
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"conform", "--profile", "bogus"}); code != ExitInput {
		t.Fatalf("expected an unknown profile to be an input error, got code=%d", code)
	}
}
