package signing

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// BundleVerificationStage distinguishes recognizing an envelope wrapper from
// cryptographic verification and trust-policy acceptance.
type BundleVerificationStage string

const (
	BundleUnrecognized              BundleVerificationStage = "UNRECOGNIZED"
	BundleRecognized                BundleVerificationStage = "RECOGNIZED"
	BundleInspected                 BundleVerificationStage = "INSPECTED"
	BundleCryptographicallyVerified BundleVerificationStage = "CRYPTOGRAPHICALLY_VERIFIED"
	BundleSignerValidated           BundleVerificationStage = "SIGNER_VALIDATED"
	BundleTrustPolicyAccepted       BundleVerificationStage = "TRUST_POLICY_ACCEPTED"
)

// BundleTrustPolicy defines the subject and builder constraints required for a
// cryptographically verified DSSE/OMS bundle to be accepted by trust policy.
type BundleTrustPolicy struct {
	ExpectedSubjectSHA256 string            `json:"expected_subject_sha256"`
	TrustedKeys           map[string]string `json:"trusted_keys"`
	AllowedPredicateTypes []string          `json:"allowed_predicate_types,omitempty"`
	AllowedBuilders       []string          `json:"allowed_builders,omitempty"`
}

// BundleVerificationReport captures the exact stage reached and every boolean
// transition so an inspected or merely recognized DSSE/OMS wrapper is never
// conflated with a verified signature.
type BundleVerificationReport struct {
	Stage                     BundleVerificationStage `json:"stage"`
	Recognized                bool                    `json:"recognized"`
	Inspected                 bool                    `json:"inspected"`
	CryptographicallyVerified bool                    `json:"cryptographically_verified"`
	SignerValidated           bool                    `json:"signer_validated"`
	TrustPolicyAccepted       bool                    `json:"trust_policy_accepted"`
	VerifiedKeyID             string                  `json:"verified_key_id,omitempty"`
	SubjectDigests            map[string]string       `json:"subject_digests,omitempty"`
	PredicateType             string                  `json:"predicate_type,omitempty"`
	BuilderID                 string                  `json:"builder_id,omitempty"`
	FailureReason             string                  `json:"failure_reason,omitempty"`
}

// VerifyDSSEBundle evaluates raw DSSE/OMS provenance bytes through the 5-stage
// verification hierarchy and returns an error unless all 5 stages succeed.
func VerifyDSSEBundle(raw []byte, policy BundleTrustPolicy) (BundleVerificationReport, error) {
	var report BundleVerificationReport
	var env skil.Provenance
	if err := json.Unmarshal(raw, &env); err != nil || strings.TrimSpace(env.PayloadType) == "" || strings.TrimSpace(env.Payload) == "" {
		report.Stage = BundleUnrecognized
		report.FailureReason = "envelope is not a recognizable DSSE/OMS bundle"
		return report, errors.New(report.FailureReason)
	}
	report.Recognized = true
	report.Stage = BundleRecognized

	stmt, err := ParseProvenance(env)
	if err != nil || len(stmt.Subject) == 0 {
		report.FailureReason = "DSSE payload is not a valid in-toto/OMS statement with subjects"
		return report, errors.New(report.FailureReason)
	}
	subjectDigests := map[string]string{}
	for _, subj := range stmt.Subject {
		if sha := strings.TrimSpace(subj.Digest["sha256"]); sha != "" {
			subjectDigests[subj.Name] = sha
		}
	}
	if len(subjectDigests) == 0 {
		report.FailureReason = "statement subjects lack sha256 digests"
		return report, errors.New(report.FailureReason)
	}
	report.Inspected = true
	report.Stage = BundleInspected
	report.SubjectDigests = subjectDigests
	report.PredicateType = stmt.PredicateType
	report.BuilderID = stmt.Predicate.RunDetails.Builder.ID

	if len(env.Signatures) == 0 {
		report.FailureReason = "DSSE bundle is unsigned (recognized and inspected only)"
		return report, errors.New(report.FailureReason)
	}
	if len(policy.TrustedKeys) == 0 {
		report.FailureReason = "no trusted keys configured for signer validation"
		return report, errors.New(report.FailureReason)
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		report.FailureReason = "invalid base64 payload"
		return report, errors.New(report.FailureReason)
	}
	pae := DSSEPAE(env.PayloadType, payloadBytes)

	verifiedKeyID := ""
	for _, sig := range env.Signatures {
		if err := verify(pae, skil.Signature{
			Provider:  Provider,
			Algorithm: Algorithm,
			KeyID:     sig.KeyID,
			Value:     sig.Sig,
		}, policy.TrustedKeys); err == nil {
			verifiedKeyID = sig.KeyID
			break
		}
	}
	if verifiedKeyID == "" {
		report.FailureReason = "cryptographic signature verification or signer trust check failed"
		return report, errors.New(report.FailureReason)
	}
	report.CryptographicallyVerified = true
	report.SignerValidated = true
	report.VerifiedKeyID = verifiedKeyID
	report.Stage = BundleSignerValidated

	// Stage 5: TrustPolicyAccepted requires subject digest binding and optional predicate/builder constraints.
	if strings.TrimSpace(policy.ExpectedSubjectSHA256) == "" {
		report.FailureReason = "trust policy requires expected_subject_sha256"
		return report, errors.New(report.FailureReason)
	}
	matchedSubject := false
	for _, sha := range subjectDigests {
		if strings.EqualFold(sha, strings.TrimPrefix(policy.ExpectedSubjectSHA256, "sha256:")) {
			matchedSubject = true
			break
		}
	}
	if !matchedSubject {
		report.FailureReason = fmt.Sprintf("bundle subject digest does not match expected artifact %q", policy.ExpectedSubjectSHA256)
		return report, errors.New(report.FailureReason)
	}
	if len(policy.AllowedPredicateTypes) > 0 && !containsStr(policy.AllowedPredicateTypes, stmt.PredicateType) {
		report.FailureReason = fmt.Sprintf("predicate type %q not permitted by trust policy", stmt.PredicateType)
		return report, errors.New(report.FailureReason)
	}
	if len(policy.AllowedBuilders) > 0 && !containsStr(policy.AllowedBuilders, report.BuilderID) {
		report.FailureReason = fmt.Sprintf("builder %q not permitted by trust policy", report.BuilderID)
		return report, errors.New(report.FailureReason)
	}

	report.TrustPolicyAccepted = true
	report.Stage = BundleTrustPolicyAccepted
	return report, nil
}

func containsStr(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}
