package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/receipt"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

const (
	InTotoStatementTypeV1            = "https://in-toto.io/Statement/v1"
	InTotoPayloadType                = "application/vnd.in-toto+json"
	AssuranceCertificatePredicateV1  = "https://skil.security/assurance-certificate/v1"
	PortableCertificateSchemaVersion = "1.0"
)

var (
	emailPIIRegex = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	ssnPIIRegex   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
)

// InTotoResourceDescriptor represents an in-toto v1 subject resource descriptor.
type InTotoResourceDescriptor struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// PortableSubjectIdentity binds the subject artifact identity and immutable SHA-256 digest.
type PortableSubjectIdentity struct {
	SubjectID    string `json:"subject_id"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Digest       string `json:"digest"`
	ArtifactType string `json:"artifact_type"`
	Source       string `json:"source,omitempty"`
}

// PortableProducerIdentity identifies the SKIL builder/producer that issued the certificate.
type PortableProducerIdentity struct {
	ProducerID string `json:"producer_id"`
	Name       string `json:"name"`
	Version    string `json:"version"`
}

// PortableScannerIdentity records the scanner version and rule-pack digest used during evaluation.
type PortableScannerIdentity struct {
	ScannerID      string `json:"scanner_id"`
	ScannerVersion string `json:"scanner_version"`
	RulePackDigest string `json:"rule_pack_digest"`
}

// PortablePolicyBinding records the upstream policy identity and canonical digest evaluated at issuance.
type PortablePolicyBinding struct {
	PolicyID     string `json:"policy_id"`
	PolicyDigest string `json:"policy_digest"`
}

// PortableEvidenceManifestEntry binds a single piece of supporting verification evidence to the subject.
type PortableEvidenceManifestEntry struct {
	EvidenceID        string `json:"evidence_id"`
	EvidenceType      string `json:"evidence_type"`
	SubjectDigest     string `json:"subject_digest"`
	Digest            string `json:"digest"`
	VerificationClass string `json:"verification_class"` // OBSERVED, INFERRED, VERIFIED, UNKNOWN
	Required          bool   `json:"required"`
}

// PortableCoverageSummary summarizes Coverage Universe completion inside a portable certificate.
type PortableCoverageSummary struct {
	Universe        skil.CoverageUniverse `json:"universe"`
	CompletionRatio float64               `json:"completion_ratio"`
	Complete        bool                  `json:"complete"`
}

// PortableValidityConditions declares the conditions under which a portable assurance certificate remains valid.
type PortableValidityConditions struct {
	ValidFrom                 time.Time         `json:"valid_from"`
	ValidUntil                time.Time         `json:"valid_until"`
	RequiredEvidenceIDs       []string          `json:"required_evidence_ids"`
	EnvironmentConstraints    map[string]string `json:"environment_constraints,omitempty"`
	MaxReconciliationInterval time.Duration     `json:"max_reconciliation_interval,omitempty"`
	UnobservedAssumptions     []string          `json:"unobserved_assumptions,omitempty"`
	ProofValid                bool              `json:"proof_valid"`
}

// Validate checks that PortableValidityConditions are complete and contain no unobserved assumptions when ProofValid is true.
func (v PortableValidityConditions) Validate() error {
	if v.ValidFrom.IsZero() || v.ValidUntil.IsZero() || !v.ValidUntil.After(v.ValidFrom) {
		return errors.New("validity_conditions requires valid_from < valid_until")
	}
	if len(v.RequiredEvidenceIDs) == 0 {
		return errors.New("validity_conditions requires non-empty required_evidence_ids")
	}
	if v.ProofValid && len(v.UnobservedAssumptions) > 0 {
		return fmt.Errorf("validity_conditions cannot claim proof_valid=true with unobserved_assumptions: %v", v.UnobservedAssumptions)
	}
	return nil
}

// PortableCertificatePredicateV1 contains the SKIL assurance predicate inside the in-toto Statement v1.
type PortableCertificatePredicateV1 struct {
	SchemaVersion       string                          `json:"schema_version"`
	Subject             PortableSubjectIdentity         `json:"subject"`
	Producer            PortableProducerIdentity        `json:"producer"`
	Scanner             PortableScannerIdentity         `json:"scanner"`
	Policy              PortablePolicyBinding           `json:"policy"`
	AssuranceState      skil.AssuranceState             `json:"assurance_state"`
	AssuranceOutcome    skil.AssuranceOutcome           `json:"assurance_outcome"`
	OutcomeProof        skil.AssuranceOutcomeProof      `json:"outcome_proof"`
	EvidenceManifest    []PortableEvidenceManifestEntry `json:"evidence_manifest"`
	CoverageSummary     PortableCoverageSummary         `json:"coverage_summary"`
	VerificationMethods []string                        `json:"verification_methods"`
	KnownLimitations    []string                        `json:"known_limitations,omitempty"`
	ValidityConditions  PortableValidityConditions      `json:"validity_conditions"`
	Dependencies        []skil.DependencyIdentity       `json:"dependencies,omitempty"`
	IssuedAt            time.Time                       `json:"issued_at"`
	ExpiresAt           time.Time                       `json:"expires_at"`
	CertificateDigest   string                          `json:"certificate_digest"`
}

// PortableAssuranceStatementV1 is an in-toto Statement v1 carrying PortableCertificatePredicateV1.
type PortableAssuranceStatementV1 struct {
	Type          string                         `json:"_type"`
	Subject       []InTotoResourceDescriptor     `json:"subject"`
	PredicateType string                         `json:"predicateType"`
	Predicate     PortableCertificatePredicateV1 `json:"predicate"`
}

// SignedPortableCertificate is a DSSE envelope carrying a signed PortableAssuranceStatementV1.
type SignedPortableCertificate struct {
	PayloadType string               `json:"payloadType"`
	Payload     string               `json:"payload"`
	Signatures  []skil.DSSESignature `json:"signatures"`
}

// ContainsSensitiveOrPIIContent inspects strings for credentials, tokens, private keys, or personal data.
func ContainsSensitiveOrPIIContent(values ...string) (bool, string) {
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if receipt.ContainsSensitiveCredentialMaterial(trimmed) {
			return true, "detected sensitive credential material in certificate metadata"
		}
		if emailPIIRegex.MatchString(trimmed) {
			return true, "detected email address (PII) in certificate metadata"
		}
		if ssnPIIRegex.MatchString(trimmed) {
			return true, "detected SSN pattern (PII) in certificate metadata"
		}
	}
	return false, ""
}

func normalizeSHA256Digest(d string) string {
	d = strings.TrimSpace(d)
	if d == "" {
		return ""
	}
	if !strings.HasPrefix(d, "sha256:") {
		return "sha256:" + d
	}
	return d
}

func isValidSHA256Digest(d string) bool {
	if !strings.HasPrefix(d, "sha256:") {
		return false
	}
	hexPart := strings.TrimPrefix(d, "sha256:")
	if len(hexPart) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}

// ComputeCertificateDigest computes the deterministic canonical SHA-256 digest of the predicate.
func (p PortableCertificatePredicateV1) ComputeCertificateDigest() (string, error) {
	clone := p
	clone.CertificateDigest = ""
	canonBytes, err := signing.CanonicalJSON(clone)
	if err != nil {
		return "", fmt.Errorf("canonicalize certificate predicate: %w", err)
	}
	sum := sha256.Sum256(canonBytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// NewPortableAssuranceStatementV1 constructs and validates a standards-based in-toto Statement v1 for a SKIL assurance certificate.
func NewPortableAssuranceStatementV1(pred PortableCertificatePredicateV1) (PortableAssuranceStatementV1, error) {
	if pred.SchemaVersion == "" {
		pred.SchemaVersion = PortableCertificateSchemaVersion
	}
	if pred.SchemaVersion != PortableCertificateSchemaVersion {
		return PortableAssuranceStatementV1{}, fmt.Errorf("unsupported portable certificate schema_version %q", pred.SchemaVersion)
	}
	pred.Subject.Digest = normalizeSHA256Digest(pred.Subject.Digest)
	if pred.Subject.SubjectID == "" || pred.Subject.Name == "" || !isValidSHA256Digest(pred.Subject.Digest) {
		return PortableAssuranceStatementV1{}, errors.New("certificate subject requires subject_id, name, and valid sha256 digest")
	}
	if pred.Producer.ProducerID == "" || pred.Producer.Name == "" || pred.Producer.Version == "" {
		return PortableAssuranceStatementV1{}, errors.New("certificate producer requires producer_id, name, and version")
	}
	pred.Scanner.RulePackDigest = normalizeSHA256Digest(pred.Scanner.RulePackDigest)
	if pred.Scanner.ScannerID == "" || pred.Scanner.ScannerVersion == "" || !isValidSHA256Digest(pred.Scanner.RulePackDigest) {
		return PortableAssuranceStatementV1{}, errors.New("certificate scanner requires scanner_id, scanner_version, and valid rule_pack_digest")
	}
	pred.Policy.PolicyDigest = normalizeSHA256Digest(pred.Policy.PolicyDigest)
	if pred.Policy.PolicyID == "" || !isValidSHA256Digest(pred.Policy.PolicyDigest) {
		return PortableAssuranceStatementV1{}, errors.New("certificate policy requires policy_id and valid policy_digest")
	}
	if pred.AssuranceState != skil.AssuranceSafe && pred.AssuranceState != skil.AssuranceUnsafe && pred.AssuranceState != skil.AssuranceUnknown {
		return PortableAssuranceStatementV1{}, fmt.Errorf("invalid assurance_state %q", pred.AssuranceState)
	}
	if pred.AssuranceOutcome != skil.OutcomeComplete &&
		pred.AssuranceOutcome != skil.OutcomePartial &&
		pred.AssuranceOutcome != skil.OutcomeFailed &&
		pred.AssuranceOutcome != skil.OutcomeNotApplicable &&
		pred.AssuranceOutcome != skil.OutcomeExcludedByPolicy {
		return PortableAssuranceStatementV1{}, fmt.Errorf("invalid assurance_outcome %q", pred.AssuranceOutcome)
	}
	if err := pred.OutcomeProof.Validate(); err != nil {
		return PortableAssuranceStatementV1{}, fmt.Errorf("invalid outcome_proof: %w", err)
	}
	// Fail-closed invariant: SAFE requires COMPLETE outcome and zero blocking/incomplete conditions.
	if pred.AssuranceState == skil.AssuranceSafe && (pred.AssuranceOutcome != skil.OutcomeComplete || pred.OutcomeProof.Outcome != skil.OutcomeComplete) {
		return PortableAssuranceStatementV1{}, fmt.Errorf("assurance_state SAFE cannot be issued when assurance_outcome is %s", pred.AssuranceOutcome)
	}
	if pred.IssuedAt.IsZero() || pred.ExpiresAt.IsZero() || !pred.ExpiresAt.After(pred.IssuedAt) {
		return PortableAssuranceStatementV1{}, errors.New("certificate requires valid issued_at and expires_at with expires_at > issued_at")
	}
	if len(pred.EvidenceManifest) == 0 {
		return PortableAssuranceStatementV1{}, errors.New("certificate requires non-empty evidence_manifest")
	}
	if len(pred.VerificationMethods) == 0 {
		return PortableAssuranceStatementV1{}, errors.New("certificate requires non-empty verification_methods")
	}
	if err := pred.ValidityConditions.Validate(); err != nil {
		return PortableAssuranceStatementV1{}, fmt.Errorf("invalid validity_conditions: %w", err)
	}

	// Normalize and validate evidence manifest entries and check for secrets/PII.
	inspectStrings := []string{
		pred.Subject.SubjectID,
		pred.Subject.Name,
		pred.Subject.Source,
		pred.Producer.ProducerID,
		pred.Producer.Name,
		pred.Scanner.ScannerID,
		pred.Policy.PolicyID,
	}
	inspectStrings = append(inspectStrings, pred.KnownLimitations...)
	inspectStrings = append(inspectStrings, pred.VerificationMethods...)
	for k, v := range pred.ValidityConditions.EnvironmentConstraints {
		inspectStrings = append(inspectStrings, k, v)
	}

	manifest := make([]PortableEvidenceManifestEntry, len(pred.EvidenceManifest))
	for i, item := range pred.EvidenceManifest {
		item.SubjectDigest = normalizeSHA256Digest(item.SubjectDigest)
		item.Digest = normalizeSHA256Digest(item.Digest)
		if item.EvidenceID == "" || item.EvidenceType == "" {
			return PortableAssuranceStatementV1{}, fmt.Errorf("evidence_manifest[%d] missing evidence_id or evidence_type", i)
		}
		if item.SubjectDigest != pred.Subject.Digest {
			return PortableAssuranceStatementV1{}, fmt.Errorf("evidence_manifest[%d] (%s) subject_digest %s does not match certificate subject digest %s", i, item.EvidenceID, item.SubjectDigest, pred.Subject.Digest)
		}
		if !isValidSHA256Digest(item.Digest) {
			return PortableAssuranceStatementV1{}, fmt.Errorf("evidence_manifest[%d] (%s) has invalid sha256 digest %q", i, item.EvidenceID, item.Digest)
		}
		switch item.VerificationClass {
		case "OBSERVED", "INFERRED", "VERIFIED", "UNKNOWN":
		default:
			return PortableAssuranceStatementV1{}, fmt.Errorf("evidence_manifest[%d] (%s) has invalid verification_class %q", i, item.EvidenceID, item.VerificationClass)
		}
		if pred.AssuranceState == skil.AssuranceSafe && item.Required && item.VerificationClass == "UNKNOWN" {
			return PortableAssuranceStatementV1{}, fmt.Errorf("assurance_state SAFE cannot depend on UNKNOWN required evidence %q", item.EvidenceID)
		}
		manifest[i] = item
		inspectStrings = append(inspectStrings, item.EvidenceID, item.EvidenceType)
	}

	if hasSensitive, reason := ContainsSensitiveOrPIIContent(inspectStrings...); hasSensitive {
		return PortableAssuranceStatementV1{}, fmt.Errorf("portable certificate rejected: %s", reason)
	}

	sort.Slice(manifest, func(i, j int) bool {
		return manifest[i].EvidenceID < manifest[j].EvidenceID
	})
	pred.EvidenceManifest = manifest

	methods := append([]string(nil), pred.VerificationMethods...)
	sort.Strings(methods)
	pred.VerificationMethods = methods

	limitations := append([]string(nil), pred.KnownLimitations...)
	sort.Strings(limitations)
	pred.KnownLimitations = limitations

	pred.IssuedAt = pred.IssuedAt.UTC()
	pred.ExpiresAt = pred.ExpiresAt.UTC()

	digest, err := pred.ComputeCertificateDigest()
	if err != nil {
		return PortableAssuranceStatementV1{}, err
	}
	pred.CertificateDigest = digest

	rawHex := strings.TrimPrefix(pred.Subject.Digest, "sha256:")
	return PortableAssuranceStatementV1{
		Type: InTotoStatementTypeV1,
		Subject: []InTotoResourceDescriptor{
			{
				Name: pred.Subject.Name,
				Digest: map[string]string{
					"sha256": rawHex,
				},
			},
		},
		PredicateType: AssuranceCertificatePredicateV1,
		Predicate:     pred,
	}, nil
}

// SignPortableCertificate signs a PortableAssuranceStatementV1 into a DSSE envelope using Ed25519.
func SignPortableCertificate(stmt PortableAssuranceStatementV1, privKey ed25519.PrivateKey, keyID string) (SignedPortableCertificate, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return SignedPortableCertificate{}, errors.New("valid ed25519 private key required to sign portable certificate")
	}
	if keyID == "" {
		keyID = signing.KeyID(privKey.Public().(ed25519.PublicKey))
	}
	canonPayload, err := signing.CanonicalJSON(stmt)
	if err != nil {
		return SignedPortableCertificate{}, fmt.Errorf("canonicalize portable statement: %w", err)
	}
	pae := signing.DSSEPAE(InTotoPayloadType, canonPayload)
	sig := ed25519.Sign(privKey, pae)
	return SignedPortableCertificate{
		PayloadType: InTotoPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(canonPayload),
		Signatures: []skil.DSSESignature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}, nil
}

// LocalVerifierPolicy specifies optional policy requirements when verifying a certificate offline.
type LocalVerifierPolicy struct {
	RequiredPolicyID            string
	RequiredPolicyDigest        string
	RequiredVerificationMethods []string
	RequireCompleteOutcome      bool
	DisallowKnownLimitations    bool
}

// OfflineCertificateVerifyOptions configures offline verification of a SignedPortableCertificate.
type OfflineCertificateVerifyOptions struct {
	ExpectedArtifactDigest string
	TrustedPublicKeys      map[string]ed25519.PublicKey
	TrustedProducers       []string
	VerifyTime             time.Time
	ClockSkew              time.Duration
	VerifierPolicy         *LocalVerifierPolicy
}

// OfflineVerificationReport captures the separated cryptographic, subject-safety, and policy-acceptance verdicts.
type OfflineVerificationReport struct {
	CryptographicallyValid bool                          `json:"cryptographically_valid"`
	SubjectSafe            bool                          `json:"subject_safe"`
	PolicyAccepted         bool                          `json:"policy_accepted"`
	VerifiedKeyID          string                        `json:"verified_key_id,omitempty"`
	CertificateDigest      string                        `json:"certificate_digest,omitempty"`
	SubjectDigest          string                        `json:"subject_digest,omitempty"`
	AssuranceState         skil.AssuranceState           `json:"assurance_state,omitempty"`
	AssuranceOutcome       skil.AssuranceOutcome         `json:"assurance_outcome,omitempty"`
	FailureReasons         []string                      `json:"failure_reasons,omitempty"`
	PolicyRejectionReasons []string                      `json:"policy_rejection_reasons,omitempty"`
	Statement              *PortableAssuranceStatementV1 `json:"statement,omitempty"`
}

// VerifyPortableCertificateOffline verifies a SignedPortableCertificate completely offline without network access.
// It strictly separates:
//  1. CryptographicallyValid (authentic DSSE signature, valid schema, intact digests, trusted signer/producer, non-expired)
//  2. SubjectSafe (CryptographicallyValid AND AssuranceState == SAFE AND AssuranceOutcome == COMPLETE AND zero blocking limitations)
//  3. PolicyAccepted (SubjectSafe AND satisfies the verifier's LocalVerifierPolicy)
func VerifyPortableCertificateOffline(env SignedPortableCertificate, opts OfflineCertificateVerifyOptions) (OfflineVerificationReport, error) {
	report := OfflineVerificationReport{}

	if env.PayloadType != InTotoPayloadType {
		reason := fmt.Sprintf("unsupported DSSE payloadType %q (expected %q)", env.PayloadType, InTotoPayloadType)
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	if len(env.Signatures) == 0 {
		reason := "missing DSSE signatures"
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	if len(opts.TrustedPublicKeys) == 0 {
		reason := "no trusted public keys configured for offline verification"
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		reason := fmt.Sprintf("decode DSSE base64 payload: %v", err)
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}

	// 1. Verify DSSE Ed25519 signature authenticity against trusted roots.
	pae := signing.DSSEPAE(env.PayloadType, payloadBytes)
	verifiedKeyID := ""
	for _, sig := range env.Signatures {
		pub, ok := opts.TrustedPublicKeys[sig.KeyID]
		if !ok || len(pub) != ed25519.PublicKeySize {
			continue
		}
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pub, pae, sigBytes) {
			verifiedKeyID = sig.KeyID
			break
		}
	}
	if verifiedKeyID == "" {
		reason := "DSSE signature verification failed against trusted public keys"
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}

	// 2. Unmarshal and verify schema compatibility.
	var stmt PortableAssuranceStatementV1
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
		reason := fmt.Sprintf("unmarshal in-toto statement: %v", err)
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	if stmt.Type != InTotoStatementTypeV1 {
		reason := fmt.Sprintf("unsupported in-toto _type %q", stmt.Type)
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	if stmt.PredicateType != AssuranceCertificatePredicateV1 {
		reason := fmt.Sprintf("unsupported predicateType %q", stmt.PredicateType)
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	if stmt.Predicate.SchemaVersion != PortableCertificateSchemaVersion {
		reason := fmt.Sprintf("unsupported predicate schema_version %q", stmt.Predicate.SchemaVersion)
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}

	pred := stmt.Predicate
	report.VerifiedKeyID = verifiedKeyID
	report.CertificateDigest = pred.CertificateDigest
	report.SubjectDigest = pred.Subject.Digest
	report.AssuranceState = pred.AssuranceState
	report.AssuranceOutcome = pred.AssuranceOutcome
	report.Statement = &stmt

	// 3. Verify trust roots (producer allowlist if configured).
	if len(opts.TrustedProducers) > 0 {
		trustedProducer := false
		for _, p := range opts.TrustedProducers {
			if p == pred.Producer.ProducerID {
				trustedProducer = true
				break
			}
		}
		if !trustedProducer {
			reason := fmt.Sprintf("untrusted producer %q", pred.Producer.ProducerID)
			report.FailureReasons = append(report.FailureReasons, reason)
			return report, errors.New(reason)
		}
	}

	// 4. Verify certificate canonical digest and evidence manifest integrity.
	expectedCertDigest, err := pred.ComputeCertificateDigest()
	if err != nil {
		reason := fmt.Sprintf("compute canonical certificate digest: %v", err)
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	if pred.CertificateDigest == "" || pred.CertificateDigest != expectedCertDigest {
		reason := fmt.Sprintf("certificate digest mismatch: recorded %s != computed %s", pred.CertificateDigest, expectedCertDigest)
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	if len(pred.EvidenceManifest) == 0 {
		reason := "certificate evidence_manifest is empty"
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}

	// 5. Verify subject binding across statement subject, predicate subject, expected artifact digest, and manifest entries.
	if len(stmt.Subject) == 0 {
		reason := "in-toto statement subject array is empty"
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	stmtSHA256 := normalizeSHA256Digest(stmt.Subject[0].Digest["sha256"])
	predSubjectDigest := normalizeSHA256Digest(pred.Subject.Digest)
	if !isValidSHA256Digest(predSubjectDigest) || stmtSHA256 != predSubjectDigest {
		reason := fmt.Sprintf("statement subject digest %q does not match predicate subject digest %q", stmtSHA256, predSubjectDigest)
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	if opts.ExpectedArtifactDigest != "" {
		expectedDigest := normalizeSHA256Digest(opts.ExpectedArtifactDigest)
		if expectedDigest != predSubjectDigest {
			reason := fmt.Sprintf("artifact integrity mismatch: expected %s, certificate bound to %s", expectedDigest, predSubjectDigest)
			report.FailureReasons = append(report.FailureReasons, reason)
			return report, errors.New(reason)
		}
	}

	manifestIDs := make(map[string]PortableEvidenceManifestEntry, len(pred.EvidenceManifest))
	for _, entry := range pred.EvidenceManifest {
		if normalizeSHA256Digest(entry.SubjectDigest) != predSubjectDigest {
			reason := fmt.Sprintf("evidence manifest entry %q bound to %s instead of subject %s", entry.EvidenceID, entry.SubjectDigest, predSubjectDigest)
			report.FailureReasons = append(report.FailureReasons, reason)
			return report, errors.New(reason)
		}
		if !isValidSHA256Digest(entry.Digest) {
			reason := fmt.Sprintf("evidence manifest entry %q has invalid digest %q", entry.EvidenceID, entry.Digest)
			report.FailureReasons = append(report.FailureReasons, reason)
			return report, errors.New(reason)
		}
		manifestIDs[entry.EvidenceID] = entry
	}
	for _, reqID := range pred.ValidityConditions.RequiredEvidenceIDs {
		if _, ok := manifestIDs[reqID]; !ok {
			reason := fmt.Sprintf("required evidence ID %q from validity_conditions is missing from evidence_manifest", reqID)
			report.FailureReasons = append(report.FailureReasons, reason)
			return report, errors.New(reason)
		}
	}

	// 6. Verify temporal validity and structural validity conditions.
	now := opts.VerifyTime
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := opts.ClockSkew
	if skew < 0 {
		skew = 0
	}
	if now.Add(skew).Before(pred.IssuedAt) {
		reason := fmt.Sprintf("certificate is not yet valid (issued_at=%s, verify_time=%s)", pred.IssuedAt.Format(time.RFC3339), now.Format(time.RFC3339))
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	if !now.Add(-skew).Before(pred.ExpiresAt) {
		reason := fmt.Sprintf("certificate has expired (expires_at=%s, verify_time=%s)", pred.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}
	if err := pred.ValidityConditions.Validate(); err != nil {
		reason := fmt.Sprintf("certificate validity_conditions invalid: %v", err)
		report.FailureReasons = append(report.FailureReasons, reason)
		return report, errors.New(reason)
	}

	// Cryptographic and structural verification succeeded!
	report.CryptographicallyValid = true

	// 7. Determine SubjectSafe (Invariant 9: valid signature NEVER implies SAFE).
	hasUnknownRequiredEvidence := false
	for _, entry := range pred.EvidenceManifest {
		if entry.Required && entry.VerificationClass == "UNKNOWN" {
			hasUnknownRequiredEvidence = true
			break
		}
	}
	outcomeProofValid := pred.OutcomeProof.Validate() == nil && pred.OutcomeProof.Outcome == skil.OutcomeComplete
	coverageComplete := pred.CoverageSummary.Complete && pred.CoverageSummary.Universe.Complete()
	if pred.AssuranceState == skil.AssuranceSafe &&
		pred.AssuranceOutcome == skil.OutcomeComplete &&
		coverageComplete &&
		outcomeProofValid &&
		!hasUnknownRequiredEvidence {
		report.SubjectSafe = true
	} else {
		report.SubjectSafe = false
		report.PolicyRejectionReasons = append(report.PolicyRejectionReasons,
			fmt.Sprintf("subject assurance is %s/%s (safe=%t, coverage_complete=%t, outcome_proof_complete=%t)",
				pred.AssuranceState, pred.AssuranceOutcome, report.SubjectSafe, coverageComplete, outcomeProofValid))
	}

	// 8. Evaluate policy acceptance separately from cryptographic validity.
	if !report.SubjectSafe {
		report.PolicyAccepted = false
		return report, nil
	}

	policyAccepted := true
	if opts.VerifierPolicy != nil {
		vp := opts.VerifierPolicy
		if vp.RequiredPolicyID != "" && pred.Policy.PolicyID != vp.RequiredPolicyID {
			policyAccepted = false
			report.PolicyRejectionReasons = append(report.PolicyRejectionReasons,
				fmt.Sprintf("policy_id %q does not match required %q", pred.Policy.PolicyID, vp.RequiredPolicyID))
		}
		if vp.RequiredPolicyDigest != "" && normalizeSHA256Digest(pred.Policy.PolicyDigest) != normalizeSHA256Digest(vp.RequiredPolicyDigest) {
			policyAccepted = false
			report.PolicyRejectionReasons = append(report.PolicyRejectionReasons,
				fmt.Sprintf("policy_digest %q does not match required %q", pred.Policy.PolicyDigest, vp.RequiredPolicyDigest))
		}
		if vp.RequireCompleteOutcome && pred.AssuranceOutcome != skil.OutcomeComplete {
			policyAccepted = false
			report.PolicyRejectionReasons = append(report.PolicyRejectionReasons,
				fmt.Sprintf("assurance_outcome %q does not satisfy RequireCompleteOutcome", pred.AssuranceOutcome))
		}
		if vp.DisallowKnownLimitations && len(pred.KnownLimitations) > 0 {
			policyAccepted = false
			report.PolicyRejectionReasons = append(report.PolicyRejectionReasons,
				fmt.Sprintf("certificate contains disallowed known_limitations: %v", pred.KnownLimitations))
		}
		methodSet := make(map[string]bool, len(pred.VerificationMethods))
		for _, m := range pred.VerificationMethods {
			methodSet[m] = true
		}
		for _, reqMethod := range vp.RequiredVerificationMethods {
			if !methodSet[reqMethod] {
				policyAccepted = false
				report.PolicyRejectionReasons = append(report.PolicyRejectionReasons,
					fmt.Sprintf("missing required verification method %q", reqMethod))
			}
		}
	}
	report.PolicyAccepted = policyAccepted
	return report, nil
}

// EnvironmentEvaluationContext represents the receiving environment's local policy and runtime context (Section 7.4).
type EnvironmentEvaluationContext struct {
	EnvironmentID               string
	LocalPolicyID               string
	LocalPolicyDigest           string
	RequiredVerificationMethods []string
	ForbiddenLimitations        []string
	RequireCompleteCoverage     bool
	MinimumCoverageRatio        float64
	EnvironmentAttributes       map[string]string
	CurrentDependencyDigests    map[string]string // package -> manifest digest
	RevokedCertificateDigests   map[string]bool
}

// ImportedCertificateDecision records the cross-environment evaluation of a portable certificate while preserving upstream provenance.
type ImportedCertificateDecision struct {
	Accepted               bool                     `json:"accepted"`
	EnvironmentID          string                   `json:"environment_id"`
	CertificateDigest      string                   `json:"certificate_digest"`
	SubjectDigest          string                   `json:"subject_digest"`
	UpstreamProducer       PortableProducerIdentity `json:"upstream_producer"`
	UpstreamScanner        PortableScannerIdentity  `json:"upstream_scanner"`
	UpstreamPolicy         PortablePolicyBinding    `json:"upstream_policy"`
	LocalPolicyID          string                   `json:"local_policy_id"`
	LocalPolicyDigest      string                   `json:"local_policy_digest"`
	CryptographicallyValid bool                     `json:"cryptographically_valid"`
	UpstreamSubjectSafe    bool                     `json:"upstream_subject_safe"`
	RejectionReasons       []string                 `json:"rejection_reasons,omitempty"`
	EvaluatedAt            time.Time                `json:"evaluated_at"`
}

// ImportCertificateForEnvironment verifies a portable certificate offline, preserves upstream provenance,
// and evaluates compatibility and policy acceptance for a receiving environment (CI/CD, Registry, K8s Admission, Runtime Gateway).
func ImportCertificateForEnvironment(
	env SignedPortableCertificate,
	verifyOpts OfflineCertificateVerifyOptions,
	localEnv EnvironmentEvaluationContext,
) (ImportedCertificateDecision, error) {
	now := verifyOpts.VerifyTime
	if now.IsZero() {
		now = time.Now().UTC()
	}

	report, err := VerifyPortableCertificateOffline(env, verifyOpts)
	decision := ImportedCertificateDecision{
		Accepted:               false,
		EnvironmentID:          localEnv.EnvironmentID,
		CertificateDigest:      report.CertificateDigest,
		SubjectDigest:          report.SubjectDigest,
		LocalPolicyID:          localEnv.LocalPolicyID,
		LocalPolicyDigest:      localEnv.LocalPolicyDigest,
		CryptographicallyValid: report.CryptographicallyValid,
		UpstreamSubjectSafe:    report.SubjectSafe,
		EvaluatedAt:            now,
	}
	if report.Statement != nil {
		decision.UpstreamProducer = report.Statement.Predicate.Producer
		decision.UpstreamScanner = report.Statement.Predicate.Scanner
		decision.UpstreamPolicy = report.Statement.Predicate.Policy
	}
	if err != nil || !report.CryptographicallyValid {
		decision.RejectionReasons = append(decision.RejectionReasons, report.FailureReasons...)
		return decision, err
	}

	pred := report.Statement.Predicate

	// 1. Check revocation list.
	if localEnv.RevokedCertificateDigests != nil && localEnv.RevokedCertificateDigests[pred.CertificateDigest] {
		decision.RejectionReasons = append(decision.RejectionReasons, fmt.Sprintf("certificate %s is revoked in environment %s", pred.CertificateDigest, localEnv.EnvironmentID))
	}

	// 2. Check upstream subject safety and verifier policy.
	if !report.SubjectSafe {
		decision.RejectionReasons = append(decision.RejectionReasons, report.PolicyRejectionReasons...)
	}
	if verifyOpts.VerifierPolicy != nil && !report.PolicyAccepted {
		decision.RejectionReasons = append(decision.RejectionReasons, report.PolicyRejectionReasons...)
	}

	// 3. Check receiving environment constraints against certificate ValidityConditions.EnvironmentConstraints.
	for k, expectedVal := range pred.ValidityConditions.EnvironmentConstraints {
		actualVal, ok := localEnv.EnvironmentAttributes[k]
		if !ok || actualVal != expectedVal {
			decision.RejectionReasons = append(decision.RejectionReasons,
				fmt.Sprintf("environment constraint mismatch for %q: certificate requires %q, environment %s has %q",
					k, expectedVal, localEnv.EnvironmentID, actualVal))
		}
	}

	// 4. Check coverage requirements.
	if localEnv.RequireCompleteCoverage && !pred.CoverageSummary.Complete {
		decision.RejectionReasons = append(decision.RejectionReasons, "receiving environment requires complete Coverage Universe")
	}
	if localEnv.MinimumCoverageRatio > 0 && pred.CoverageSummary.CompletionRatio < localEnv.MinimumCoverageRatio {
		decision.RejectionReasons = append(decision.RejectionReasons,
			fmt.Sprintf("coverage completion ratio %.2f is below environment minimum %.2f",
				pred.CoverageSummary.CompletionRatio, localEnv.MinimumCoverageRatio))
	}

	// 5. Check required verification methods in receiving environment.
	methodSet := make(map[string]bool, len(pred.VerificationMethods))
	for _, m := range pred.VerificationMethods {
		methodSet[m] = true
	}
	for _, req := range localEnv.RequiredVerificationMethods {
		if !methodSet[req] {
			decision.RejectionReasons = append(decision.RejectionReasons,
				fmt.Sprintf("environment %s requires verification method %q not present in certificate", localEnv.EnvironmentID, req))
		}
	}

	// 6. Check forbidden limitations.
	if len(localEnv.ForbiddenLimitations) > 0 && len(pred.KnownLimitations) > 0 {
		forbidden := make(map[string]bool, len(localEnv.ForbiddenLimitations))
		for _, f := range localEnv.ForbiddenLimitations {
			forbidden[f] = true
		}
		for _, lim := range pred.KnownLimitations {
			if forbidden["*"] || forbidden[lim] {
				decision.RejectionReasons = append(decision.RejectionReasons,
					fmt.Sprintf("certificate limitation %q is forbidden in environment %s", lim, localEnv.EnvironmentID))
			}
		}
	}

	// 7. Check dependency digests against receiving environment's current dependency state.
	if len(localEnv.CurrentDependencyDigests) > 0 {
		for _, dep := range pred.Dependencies {
			if currentDigest, exists := localEnv.CurrentDependencyDigests[dep.Package]; exists {
				if dep.ManifestDigest != "" && currentDigest != dep.ManifestDigest {
					decision.RejectionReasons = append(decision.RejectionReasons,
						fmt.Sprintf("dependency %q drifted in environment %s: certificate=%s current=%s",
							dep.Package, localEnv.EnvironmentID, dep.ManifestDigest, currentDigest))
				}
			}
		}
	}

	decision.Accepted = len(decision.RejectionReasons) == 0
	return decision, nil
}
