package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
	"testing"
)

func TestPolicyDeniesSeverityAndMissingCoverage(t *testing.T) {
	p := Policy{Version: 1, MaximumSeverity: "MEDIUM", RequiredAnalysis: []string{"ast"}}
	result := Check(p, Input{Scan: skil.ScanResult{Maximum: skil.SeverityHigh, Coverage: map[string]skil.CoverageState{}}})
	if result.Decision != "DENY" || len(result.Violations) != 2 {
		t.Fatalf("%#v", result)
	}
}

func TestPolicyDeniesIncompleteInspection(t *testing.T) {
	result := Check(Policy{Version: 1, MaximumSeverity: "CRITICAL", MinimumInspectionCompleteness: 1}, Input{
		Scan: skil.ScanResult{
			Maximum:      skil.SeverityInfo,
			Completeness: skil.InspectionSummary{Applicable: 2, Completed: 1, Skipped: 1, Completeness: .5},
		},
	})
	if result.Decision != "DENY" || len(result.Violations) != 1 ||
		result.Violations[0].Rule != "inspection-completeness" {
		t.Fatalf("unexpected policy result: %#v", result)
	}
}

func TestPolicyDeniesLowAnalyzability(t *testing.T) {
	result := Check(Policy{Version: 1, MaximumSeverity: "CRITICAL", MinimumAnalyzability: .9}, Input{
		Scan: skil.ScanResult{
			Maximum:    skil.SeverityInfo,
			Analyzable: skil.AnalyzabilitySummary{Files: 2, Full: 1, Opaque: 1, Coverage: .5},
		},
	})
	if result.Decision != "DENY" || len(result.Violations) != 1 ||
		result.Violations[0].Rule != "minimum-analyzability" {
		t.Fatalf("unexpected policy result: %#v", result)
	}
}

func TestPolicyAllowsSufficientAnalyzability(t *testing.T) {
	result := Check(Policy{Version: 1, MaximumSeverity: "CRITICAL", MinimumAnalyzability: .5}, Input{
		Scan: skil.ScanResult{
			Maximum:    skil.SeverityInfo,
			Analyzable: skil.AnalyzabilitySummary{Files: 2, Full: 1, Opaque: 1, Coverage: .5},
		},
	})
	if result.Decision != "ALLOW" {
		t.Fatalf("expected ALLOW at exactly the minimum, got: %#v", result)
	}
}

func TestPolicyDeniesOpaqueExecutableContentWhenConfigured(t *testing.T) {
	result := Check(Policy{Version: 1, MaximumSeverity: "CRITICAL", DenyOpaqueExecutableContent: true}, Input{
		Scan: skil.ScanResult{
			Maximum: skil.SeverityInfo,
			Analyzability: []skil.AnalyzabilityRecord{
				{Path: "tool.exe", State: skil.AnalyzabilityOpaque, BinaryKind: "Windows PE executable", Reason: "opaque"},
				{Path: "logo.png", State: skil.AnalyzabilityOpaque, Reason: "opaque"},
			},
		},
	})
	if result.Decision != "DENY" || len(result.Violations) != 1 || result.Violations[0].Observed != "tool.exe" {
		t.Fatalf("expected exactly one violation for the executable, not the inert binary: %#v", result)
	}
}

func TestPolicyAllowsOpaqueNonExecutableContentByDefault(t *testing.T) {
	result := Check(Policy{Version: 1, MaximumSeverity: "CRITICAL", DenyOpaqueExecutableContent: true}, Input{
		Scan: skil.ScanResult{
			Maximum: skil.SeverityInfo,
			Analyzability: []skil.AnalyzabilityRecord{
				{Path: "logo.png", State: skil.AnalyzabilityOpaque, Reason: "opaque"},
			},
		},
	})
	if result.Decision != "ALLOW" {
		t.Fatalf("expected ALLOW: opaque non-executable content should not trip deny_opaque_executable_content: %#v", result)
	}
}

func TestPolicyDeniesBudgetExhaustedWhenConfigured(t *testing.T) {
	result := Check(Policy{Version: 1, MaximumSeverity: "CRITICAL", DenyBudgetExhausted: true}, Input{
		Scan: skil.ScanResult{
			Maximum: skil.SeverityInfo,
			Budget:  skil.AnalysisBudgetUsage{Exceeded: []string{"findings", "wall_time"}},
		},
	})
	if result.Decision != "DENY" || len(result.Violations) != 1 || result.Violations[0].Observed != "findings, wall_time" {
		t.Fatalf("expected exactly one violation naming the exceeded dimensions: %#v", result)
	}
}

func TestPolicyAllowsBudgetExhaustedByDefault(t *testing.T) {
	result := Check(Policy{Version: 1, MaximumSeverity: "CRITICAL"}, Input{
		Scan: skil.ScanResult{
			Maximum: skil.SeverityInfo,
			Budget:  skil.AnalysisBudgetUsage{Exceeded: []string{"findings"}},
		},
	})
	if result.Decision != "ALLOW" {
		t.Fatalf("expected ALLOW: an exceeded budget must not deny unless deny_budget_exhausted is set: %#v", result)
	}
}

func TestPolicyDeniesRevokedArtifactDigest(t *testing.T) {
	p := Policy{Version: 1, MaximumSeverity: "CRITICAL", RevokedArtifactDigests: []string{"deadbeef"}}
	result := Check(p, Input{Scan: skil.ScanResult{
		Maximum: skil.SeverityInfo, Artifact: skil.Artifact{Digest: "deadbeef"},
	}})
	if result.Decision != "DENY" || len(result.Violations) != 1 || result.Violations[0].Rule != "revoked-artifact" {
		t.Fatalf("expected a revoked artifact digest to deny regardless of otherwise clean findings: %#v", result)
	}
}

func TestPolicyDeniesRevokedSkillByNameOrVersion(t *testing.T) {
	p := Policy{Version: 1, MaximumSeverity: "CRITICAL", RevokedSkills: []string{"bad-skill@1.0.0"}}
	result := Check(p, Input{
		Scan:     skil.ScanResult{Maximum: skil.SeverityInfo},
		Contract: &skil.SkillContract{Skill: skil.SkillIdentity{Name: "bad-skill", Version: "1.0.0"}},
	})
	if result.Decision != "DENY" || !hasViolationRule(result, "revoked-skill") {
		t.Fatalf("expected a revoked skill@version to deny: %#v", result)
	}

	pByName := Policy{Version: 1, MaximumSeverity: "CRITICAL", RevokedSkills: []string{"bad-skill"}}
	resultByName := Check(pByName, Input{
		Scan:     skil.ScanResult{Maximum: skil.SeverityInfo},
		Contract: &skil.SkillContract{Skill: skil.SkillIdentity{Name: "bad-skill", Version: "2.0.0"}},
	})
	if resultByName.Decision != "DENY" || !hasViolationRule(resultByName, "revoked-skill") {
		t.Fatalf("expected a bare revoked skill name to deny any version: %#v", resultByName)
	}
}

func TestPolicyDeniesRevokedSignerKeyEvenWithValidPackageSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := skil.PackageStatement{
		Version: 1, Name: "n", VersionName: "v",
		PackageSHA256: "pkg", ContentManifestSHA256: "content", Timestamp: time.Now(),
	}
	if err := signing.SignPackageStatement(&statement, privateKey, "revoked-key"); err != nil {
		t.Fatal(err)
	}
	p := Policy{
		Version: 1, MaximumSeverity: "CRITICAL",
		TrustedSigners:      map[string]string{"revoked-key": base64.StdEncoding.EncodeToString(publicKey)},
		RevokedSignerKeyIDs: []string{"revoked-key"},
	}
	result := Check(p, Input{
		Scan:             skil.ScanResult{Maximum: skil.SeverityInfo, Artifact: skil.Artifact{Digest: "content", PackageDigest: "pkg"}},
		PackageStatement: &statement,
	})
	if result.Decision != "DENY" || !hasViolationRule(result, "revoked-signer") {
		t.Fatalf("expected a revoked signer key to deny even with an otherwise valid signature: %#v", result)
	}
}

func TestPolicyAllowsUnrevokedArtifactSkillAndSigner(t *testing.T) {
	p := Policy{Version: 1, MaximumSeverity: "CRITICAL", RevokedArtifactDigests: []string{"other-digest"}, RevokedSkills: []string{"other-skill"}}
	result := Check(p, Input{
		Scan:     skil.ScanResult{Maximum: skil.SeverityInfo, Artifact: skil.Artifact{Digest: "clean-digest"}},
		Contract: &skil.SkillContract{Skill: skil.SkillIdentity{Name: "clean-skill", Version: "1.0.0"}},
	})
	if result.Decision != "ALLOW" {
		t.Fatalf("expected an unrevoked artifact/skill to be unaffected by an unrelated revocation list: %#v", result)
	}
}

func hasViolationRule(result Result, rule string) bool {
	for _, violation := range result.Violations {
		if violation.Rule == rule {
			return true
		}
	}
	return false
}

func TestPolicyCountsOnlySignedBoundExternalScannerEvidence(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := signing.KeyID(publicKey)
	payload := json.RawMessage(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","version":"1"}},"results":[],"properties":{"skil_subject_digest":"abc"}}]}`)
	payloadHash := sha256.Sum256(payload)
	bundle := skil.EvidenceBundle{Version: 1, Evidence: skil.Evidence{
		Type: "external-security-scan", Producer: "semgrep", ProducerVer: "1", SubjectDigest: "abc",
		Timestamp: time.Now().UTC(), PayloadDigest: hex.EncodeToString(payloadHash[:]),
		Result: skil.EvidenceResult{Status: skil.StatusPass, MaximumSeverity: skil.SeverityInfo, Findings: 0},
	}, Payload: payload}
	if err := signing.SignEvidenceBundle(&bundle, privateKey, keyID); err != nil {
		t.Fatal(err)
	}
	p := Policy{
		Version: 1, MaximumSeverity: "CRITICAL", MinimumScans: 2,
		TrustedScanners:    []string{"skil", "semgrep"},
		TrustedSigners:     map[string]string{keyID: base64.StdEncoding.EncodeToString(publicKey)},
		TrustedScannerKeys: map[string][]string{"semgrep": {keyID}},
	}
	scan := skil.ScanResult{Artifact: skil.Artifact{Digest: "abc"}, Maximum: skil.SeverityInfo, Scanners: []string{"skil"}}
	if result := Check(p, Input{Scan: scan, ExternalEvidence: []skil.EvidenceBundle{bundle}}); result.Decision != "ALLOW" {
		t.Fatalf("valid external evidence denied: %#v", result)
	}
	bundle.Evidence.SubjectDigest = "other"
	if result := Check(p, Input{Scan: scan, ExternalEvidence: []skil.EvidenceBundle{bundle}}); result.Decision != "DENY" {
		t.Fatal("rebound evidence must be denied")
	}
	bundle.Evidence.SubjectDigest = "abc"
	bundle.Evidence.Result.Status = skil.StatusFail
	if err := signing.SignEvidenceBundle(&bundle, privateKey, keyID); err != nil {
		t.Fatal(err)
	}
	if result := Check(p, Input{Scan: scan, ExternalEvidence: []skil.EvidenceBundle{bundle}}); result.Decision != "DENY" {
		t.Fatal("a signed failing scanner verdict must not count")
	}
	bundle.Evidence.Result.Status = skil.StatusPass
	if err := signing.SignEvidenceBundle(&bundle, privateKey, keyID); err != nil {
		t.Fatal(err)
	}
	p.TrustedScannerKeys["semgrep"] = []string{"sha256:other"}
	if result := Check(p, Input{Scan: scan, ExternalEvidence: []skil.EvidenceBundle{bundle}}); result.Decision != "DENY" {
		t.Fatal("a globally trusted but scanner-unbound key must not count")
	}
}

func TestPolicyCryptographicallyVerifiesTrustedSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := signing.KeyID(publicKey)
	statement := skil.PackageStatement{Version: 1, Name: "skill", PackageSHA256: "abc", ContentManifestSHA256: "content"}
	if err := signing.SignPackageStatement(&statement, privateKey, keyID); err != nil {
		t.Fatal(err)
	}
	p := Policy{Version: 1, MaximumSeverity: "CRITICAL", RequireSignature: true,
		TrustedSigners: map[string]string{keyID: base64.StdEncoding.EncodeToString(publicKey)}}
	scan := skil.ScanResult{Artifact: skil.Artifact{Digest: "content", PackageDigest: "abc"}, Maximum: skil.SeverityInfo}
	if result := Check(p, Input{Scan: scan, PackageStatement: &statement}); result.Decision != "ALLOW" {
		t.Fatalf("valid trusted signature denied: %#v", result)
	}
	statement.Name = "tampered"
	if result := Check(p, Input{Scan: scan, PackageStatement: &statement}); result.Decision != "DENY" {
		t.Fatal("tampered signature must be denied")
	}
}

func TestPolicyRejectsSignatureMetadataWithoutCryptographicProof(t *testing.T) {
	attestation := skil.Attestation{
		Version: 1, Subject: skil.Subject{Name: "skill", SHA256: "abc"},
		Signature: &skil.Signature{Provider: signing.Provider, Algorithm: signing.Algorithm, KeyID: "attacker", Value: "not-a-signature"},
	}
	p := Policy{Version: 1, MaximumSeverity: "CRITICAL", RequireSignature: true}
	scan := skil.ScanResult{Artifact: skil.Artifact{Digest: "abc"}, Maximum: skil.SeverityInfo}
	if result := Check(p, Input{Scan: scan, Attestation: &attestation}); result.Decision != "DENY" {
		t.Fatal("signature metadata alone must never satisfy policy")
	}
}

func TestPolicyGatesContainmentEvidence(t *testing.T) {
	zero := 0.0
	artifact := skil.Artifact{Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	scan := skil.ScanResult{Artifact: artifact, Maximum: skil.SeverityInfo}
	p := Policy{
		Version: 1, MaximumSeverity: "CRITICAL", RequireBehavioralEvaluation: true,
		RequireContainmentEvaluation: true, RequireRuntimeEnforcement: true,
		RequireNativeIsolation: true, MaximumContainmentViolationRate: &zero,
		RequireZeroForbiddenSideEffects: true,
	}
	if result := Check(p, Input{Scan: scan}); result.Decision != "DENY" {
		t.Fatal("missing required evaluation must be denied")
	}
	compliance := 1.0
	evaluation := skil.EvalResult{
		ArtifactDigest: artifact.Digest,
		Coverage: skil.EvalCoverage{
			Behavioral: skil.CoverageCompleted, Containment: skil.CoverageCompleted,
			Enforcement: skil.CoverageCompleted, NativeIsolation: skil.CoverageCompleted,
		},
		Metrics: skil.EvalMetrics{ContainmentComplianceRate: &compliance},
	}
	if result := Check(p, Input{Scan: scan, Eval: &evaluation}); result.Decision != "ALLOW" {
		t.Fatalf("complete compliant evaluation denied: %#v", result)
	}
	evaluation.Runs = []skil.EvalRun{{Trace: skil.EvalTrace{ContainmentViolations: []skil.ContainmentViolation{{
		Category: skil.AttackUnauthorizedExternalAction, SideEffect: true,
	}}}}}
	if result := Check(p, Input{Scan: scan, Eval: &evaluation}); result.Decision != "DENY" {
		t.Fatal("forbidden side effect must be denied")
	}
}
