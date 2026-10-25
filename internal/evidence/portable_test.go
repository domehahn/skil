package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

func sampleValidPredicate(now time.Time) PortableCertificatePredicateV1 {
	subjectDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	return PortableCertificatePredicateV1{
		SchemaVersion: PortableCertificateSchemaVersion,
		Subject: PortableSubjectIdentity{
			SubjectID:    "skill:prod/finance-assistant",
			Name:         "finance-assistant",
			Version:      "1.4.2",
			Digest:       subjectDigest,
			ArtifactType: "skill-bundle",
			Source:       "git+https://example.org/skills/finance-assistant",
		},
		Producer: PortableProducerIdentity{
			ProducerID: "skil-ci-builder-eu-central-1",
			Name:       "skil",
			Version:    "2.5.0",
		},
		Scanner: PortableScannerIdentity{
			ScannerID:      "skil-assurance-scanner",
			ScannerVersion: "2.5.0",
			RulePackDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		},
		Policy: PortablePolicyBinding{
			PolicyID:     "enterprise-strict-v3",
			PolicyDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		},
		AssuranceState:   skil.AssuranceSafe,
		AssuranceOutcome: skil.OutcomeComplete,
		OutcomeProof: skil.AssuranceOutcomeProof{
			Outcome:  skil.OutcomeComplete,
			Evidence: []string{"ev-static-ast-01", "ev-isolated-sandbox-02"},
		},
		EvidenceManifest: []PortableEvidenceManifestEntry{
			{
				EvidenceID:        "ev-static-ast-01",
				EvidenceType:      "static-analysis",
				SubjectDigest:     subjectDigest,
				Digest:            "sha256:4444444444444444444444444444444444444444444444444444444444444444",
				VerificationClass: "VERIFIED",
				Required:          true,
			},
			{
				EvidenceID:        "ev-isolated-sandbox-02",
				EvidenceType:      "behavioral-eval",
				SubjectDigest:     subjectDigest,
				Digest:            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
				VerificationClass: "VERIFIED",
				Required:          true,
			},
		},
		CoverageSummary: PortableCoverageSummary{
			Universe: skil.CoverageUniverse{
				Subjects: []skil.CoverageSubject{
					{
						ID:             "skill:prod/finance-assistant",
						PhysicalDigest: subjectDigest,
						Source:         "SKILL.md",
						Owner:          "skil-assurance-scanner",
						Disposition:    skil.CoverageDiscovered,
						Required:       true,
						Evidence:       []string{"ev-static-ast-01"},
					},
				},
			},
			CompletionRatio: 1.0,
			Complete:        true,
		},
		VerificationMethods: []string{"static-ast", "taint-flow", "isolated-behavioral", "runtime-gateway-receipt"},
		ValidityConditions: PortableValidityConditions{
			ValidFrom:           now.Add(-5 * time.Minute),
			ValidUntil:          now.Add(24 * time.Hour),
			RequiredEvidenceIDs: []string{"ev-static-ast-01", "ev-isolated-sandbox-02"},
			EnvironmentConstraints: map[string]string{
				"isolation_tier": "gvisor-or-microvm",
				"egress_policy":  "strict-allowlist",
			},
			MaxReconciliationInterval: 10 * time.Minute,
			ProofValid:                true,
		},
		Dependencies: []skil.DependencyIdentity{
			{
				Ecosystem:      "pypi",
				Package:        "httpx",
				Version:        "0.27.0",
				ManifestDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666",
			},
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
	}
}

func TestPortableCertificate_SignAndOfflineVerifySuccess(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	keyID := signing.KeyID(pub)
	now := time.Now().UTC().Truncate(time.Second)

	pred := sampleValidPredicate(now)
	stmt, err := NewPortableAssuranceStatementV1(pred)
	if err != nil {
		t.Fatalf("NewPortableAssuranceStatementV1 failed: %v", err)
	}
	if stmt.Type != InTotoStatementTypeV1 {
		t.Fatalf("expected _type %s, got %s", InTotoStatementTypeV1, stmt.Type)
	}
	if stmt.PredicateType != AssuranceCertificatePredicateV1 {
		t.Fatalf("expected predicateType %s, got %s", AssuranceCertificatePredicateV1, stmt.PredicateType)
	}

	signed, err := SignPortableCertificate(stmt, priv, keyID)
	if err != nil {
		t.Fatalf("SignPortableCertificate failed: %v", err)
	}

	report, err := VerifyPortableCertificateOffline(signed, OfflineCertificateVerifyOptions{
		ExpectedArtifactDigest: pred.Subject.Digest,
		TrustedPublicKeys:      map[string]ed25519.PublicKey{keyID: pub},
		TrustedProducers:       []string{"skil-ci-builder-eu-central-1"},
		VerifyTime:             now.Add(10 * time.Minute),
		VerifierPolicy: &LocalVerifierPolicy{
			RequiredPolicyID:            "enterprise-strict-v3",
			RequiredVerificationMethods: []string{"static-ast", "isolated-behavioral"},
			RequireCompleteOutcome:      true,
			DisallowKnownLimitations:    true,
		},
	})
	if err != nil {
		t.Fatalf("VerifyPortableCertificateOffline returned unexpected error: %v", err)
	}
	if !report.CryptographicallyValid || !report.SubjectSafe || !report.PolicyAccepted {
		t.Fatalf("expected CryptographicallyValid=true, SubjectSafe=true, PolicyAccepted=true; got %+v", report)
	}
}

func TestPortableCertificate_ValidSignatureDoesNotImplySafe(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyID := signing.KeyID(pub)
	now := time.Now().UTC().Truncate(time.Second)

	// Case 1: UNSAFE subject signed with a valid trusted key.
	unsafePred := sampleValidPredicate(now)
	unsafePred.AssuranceState = skil.AssuranceUnsafe
	unsafePred.AssuranceOutcome = skil.OutcomeFailed
	unsafePred.OutcomeProof = skil.AssuranceOutcomeProof{
		Outcome:    skil.OutcomeFailed,
		Evidence:   []string{"ev-static-ast-01"},
		Unresolved: []string{"critical-command-injection-finding"},
	}

	stmtUnsafe, err := NewPortableAssuranceStatementV1(unsafePred)
	if err != nil {
		t.Fatalf("NewPortableAssuranceStatementV1 for UNSAFE failed: %v", err)
	}
	signedUnsafe, err := SignPortableCertificate(stmtUnsafe, priv, keyID)
	if err != nil {
		t.Fatalf("SignPortableCertificate failed: %v", err)
	}

	reportUnsafe, err := VerifyPortableCertificateOffline(signedUnsafe, OfflineCertificateVerifyOptions{
		ExpectedArtifactDigest: unsafePred.Subject.Digest,
		TrustedPublicKeys:      map[string]ed25519.PublicKey{keyID: pub},
		VerifyTime:             now.Add(1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("expected no cryptographic error for authentically signed UNSAFE certificate, got: %v", err)
	}
	if !reportUnsafe.CryptographicallyValid {
		t.Fatalf("expected CryptographicallyValid=true for authentically signed UNSAFE certificate")
	}
	if reportUnsafe.SubjectSafe {
		t.Fatalf("INVARIANT VIOLATION: valid cryptographic signature on UNSAFE subject must never set SubjectSafe=true")
	}
	if reportUnsafe.PolicyAccepted {
		t.Fatalf("INVARIANT VIOLATION: valid cryptographic signature on UNSAFE subject must never set PolicyAccepted=true")
	}

	// Case 2: PARTIAL / UNKNOWN subject signed with a valid trusted key.
	partialPred := sampleValidPredicate(now)
	partialPred.AssuranceState = skil.AssuranceUnknown
	partialPred.AssuranceOutcome = skil.OutcomePartial
	partialPred.OutcomeProof = skil.AssuranceOutcomeProof{
		Outcome:    skil.OutcomePartial,
		Evidence:   []string{"ev-static-ast-01"},
		Unresolved: []string{"behavioral-sandbox-skipped"},
	}
	partialPred.CoverageSummary.Complete = false
	partialPred.CoverageSummary.CompletionRatio = 0.75

	stmtPartial, err := NewPortableAssuranceStatementV1(partialPred)
	if err != nil {
		t.Fatalf("NewPortableAssuranceStatementV1 for PARTIAL failed: %v", err)
	}
	signedPartial, err := SignPortableCertificate(stmtPartial, priv, keyID)
	if err != nil {
		t.Fatalf("SignPortableCertificate failed: %v", err)
	}

	reportPartial, err := VerifyPortableCertificateOffline(signedPartial, OfflineCertificateVerifyOptions{
		ExpectedArtifactDigest: partialPred.Subject.Digest,
		TrustedPublicKeys:      map[string]ed25519.PublicKey{keyID: pub},
		VerifyTime:             now.Add(1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("expected no cryptographic error for authentically signed PARTIAL certificate, got: %v", err)
	}
	if !reportPartial.CryptographicallyValid || reportPartial.SubjectSafe || reportPartial.PolicyAccepted {
		t.Fatalf("expected CryptographicallyValid=true, SubjectSafe=false, PolicyAccepted=false for PARTIAL certificate, got %+v", reportPartial)
	}
}

func TestPortableCertificate_RejectsSecretsAndPII(t *testing.T) {
	now := time.Now().UTC()

	predWithToken := sampleValidPredicate(now)
	predWithToken.KnownLimitations = []string{"tested with token ghp_1234567890abcdefghijklmnopqrstuvwx"}
	if _, err := NewPortableAssuranceStatementV1(predWithToken); err == nil {
		t.Fatalf("expected certificate containing GitHub token to be rejected")
	}

	predWithEmail := sampleValidPredicate(now)
	predWithEmail.Subject.Source = "owned by alice.smith@example.com"
	if _, err := NewPortableAssuranceStatementV1(predWithEmail); err == nil {
		t.Fatalf("expected certificate containing PII email address to be rejected")
	}
}

func TestPortableCertificate_RejectsTamperingAndExpiration(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	keyID := signing.KeyID(pub)
	now := time.Now().UTC().Truncate(time.Second)

	pred := sampleValidPredicate(now)
	stmt, err := NewPortableAssuranceStatementV1(pred)
	if err != nil {
		t.Fatalf("NewPortableAssuranceStatementV1 failed: %v", err)
	}
	signed, err := SignPortableCertificate(stmt, priv, keyID)
	if err != nil {
		t.Fatalf("SignPortableCertificate failed: %v", err)
	}

	// 1. Wrong artifact digest
	_, err = VerifyPortableCertificateOffline(signed, OfflineCertificateVerifyOptions{
		ExpectedArtifactDigest: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
		TrustedPublicKeys:      map[string]ed25519.PublicKey{keyID: pub},
		VerifyTime:             now.Add(1 * time.Minute),
	})
	if err == nil || !strings.Contains(err.Error(), "artifact integrity mismatch") {
		t.Fatalf("expected artifact integrity mismatch error, got: %v", err)
	}

	// 2. Untrusted public key
	_, err = VerifyPortableCertificateOffline(signed, OfflineCertificateVerifyOptions{
		ExpectedArtifactDigest: pred.Subject.Digest,
		TrustedPublicKeys:      map[string]ed25519.PublicKey{"untrusted": otherPub},
		VerifyTime:             now.Add(1 * time.Minute),
	})
	if err == nil || !strings.Contains(err.Error(), "DSSE signature verification failed") {
		t.Fatalf("expected signature verification failure, got: %v", err)
	}

	// 3. Expired certificate
	_, err = VerifyPortableCertificateOffline(signed, OfflineCertificateVerifyOptions{
		ExpectedArtifactDigest: pred.Subject.Digest,
		TrustedPublicKeys:      map[string]ed25519.PublicKey{keyID: pub},
		VerifyTime:             now.Add(48 * time.Hour),
	})
	if err == nil || !strings.Contains(err.Error(), "certificate has expired") {
		t.Fatalf("expected expiration error, got: %v", err)
	}
}

func TestPortableCertificate_CrossEnvironmentPortability(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyID := signing.KeyID(pub)
	now := time.Now().UTC().Truncate(time.Second)

	pred := sampleValidPredicate(now)
	stmt, err := NewPortableAssuranceStatementV1(pred)
	if err != nil {
		t.Fatalf("NewPortableAssuranceStatementV1 failed: %v", err)
	}
	signed, err := SignPortableCertificate(stmt, priv, keyID)
	if err != nil {
		t.Fatalf("SignPortableCertificate failed: %v", err)
	}

	verifyOpts := OfflineCertificateVerifyOptions{
		ExpectedArtifactDigest: pred.Subject.Digest,
		TrustedPublicKeys:      map[string]ed25519.PublicKey{keyID: pub},
		TrustedProducers:       []string{"skil-ci-builder-eu-central-1"},
		VerifyTime:             now.Add(5 * time.Minute),
	}

	// Compatible receiving environment (e.g., Kubernetes admission controller)
	k8sDecision, err := ImportCertificateForEnvironment(signed, verifyOpts, EnvironmentEvaluationContext{
		EnvironmentID:               "k8s-prod-eu-central-1",
		LocalPolicyID:               "k8s-admission-policy-v2",
		LocalPolicyDigest:           "sha256:7777777777777777777777777777777777777777777777777777777777777777",
		RequiredVerificationMethods: []string{"static-ast", "isolated-behavioral"},
		RequireCompleteCoverage:     true,
		MinimumCoverageRatio:        1.0,
		EnvironmentAttributes: map[string]string{
			"isolation_tier": "gvisor-or-microvm",
			"egress_policy":  "strict-allowlist",
		},
		CurrentDependencyDigests: map[string]string{
			"httpx": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
		},
	})
	if err != nil {
		t.Fatalf("ImportCertificateForEnvironment returned error: %v", err)
	}
	if !k8sDecision.Accepted {
		t.Fatalf("expected compatible environment to accept certificate, got rejections: %v", k8sDecision.RejectionReasons)
	}
	// Verify upstream provenance is preserved alongside local policy evaluation
	if k8sDecision.UpstreamProducer.ProducerID != "skil-ci-builder-eu-central-1" ||
		k8sDecision.UpstreamPolicy.PolicyID != "enterprise-strict-v3" ||
		k8sDecision.LocalPolicyID != "k8s-admission-policy-v2" {
		t.Fatalf("upstream provenance or local policy not preserved: %+v", k8sDecision)
	}

	// Incompatible receiving environment (drifted dependency + weaker isolation tier)
	incompatibleDecision, err := ImportCertificateForEnvironment(signed, verifyOpts, EnvironmentEvaluationContext{
		EnvironmentID: "local-dev-host",
		LocalPolicyID: "local-policy-v1",
		EnvironmentAttributes: map[string]string{
			"isolation_tier": "host-process",
			"egress_policy":  "strict-allowlist",
		},
		CurrentDependencyDigests: map[string]string{
			"httpx": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	})
	if err != nil {
		t.Fatalf("unexpected cryptographic error: %v", err)
	}
	if incompatibleDecision.Accepted {
		t.Fatalf("expected incompatible environment and drifted dependency to reject certificate")
	}
	if len(incompatibleDecision.RejectionReasons) < 2 {
		t.Fatalf("expected at least 2 rejection reasons (isolation_tier + dependency drift), got: %v", incompatibleDecision.RejectionReasons)
	}
}
