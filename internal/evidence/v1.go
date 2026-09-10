package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/internal/trust"
	"github.com/domehahn/skil/pkg/skil"
)

const (
	SchemaVersionV1  = "1.0"
	EvidenceProvider = "skil"
	PayloadTypeV1    = "application/vnd.skil.security-evidence.v1+json"
)

type SubjectV1 struct {
	Digest       string `json:"digest" yaml:"digest"`
	ArtifactType string `json:"artifact_type" yaml:"artifact_type"`
	Name         string `json:"name,omitempty" yaml:"name,omitempty"`
	Version      string `json:"version,omitempty" yaml:"version,omitempty"`
}

type ScanSummaryV1 struct {
	Status        string `json:"status" yaml:"status"`
	Verdict       string `json:"verdict" yaml:"verdict"`
	CriticalCount int    `json:"critical_count" yaml:"critical_count"`
	HighCount     int    `json:"high_count" yaml:"high_count"`
	MediumCount   int    `json:"medium_count" yaml:"medium_count"`
	LowCount      int    `json:"low_count" yaml:"low_count"`
}

type VerificationSummaryV1 struct {
	DeclaredVsObservedMatch bool     `json:"declared_vs_observed_match" yaml:"declared_vs_observed_match"`
	Mismatches              []string `json:"mismatches" yaml:"mismatches"`
}

type AssuranceSummaryV1 struct {
	ClosureState               string  `json:"closure_state" yaml:"closure_state"`
	CompletenessClassification string  `json:"completeness_classification" yaml:"completeness_classification"`
	CompletionRatio            float64 `json:"completion_ratio" yaml:"completion_ratio"`
}

type RiskSummaryV1 struct {
	TrustScore float64 `json:"trust_score" yaml:"trust_score"`
	TrustLevel string  `json:"trust_level" yaml:"trust_level"`
}

// SecurityEvidenceV1 is the canonical versioned public security evidence schema produced by SKIL.
type SecurityEvidenceV1 struct {
	SchemaVersion   string                `json:"schema_version" yaml:"schema_version"`
	Provider        string                `json:"provider" yaml:"provider"`
	ProviderVersion string                `json:"provider_version" yaml:"provider_version"`
	Subject         SubjectV1             `json:"subject" yaml:"subject"`
	Scan            ScanSummaryV1         `json:"scan" yaml:"scan"`
	Verification    VerificationSummaryV1 `json:"verification" yaml:"verification"`
	Assurance       AssuranceSummaryV1    `json:"assurance" yaml:"assurance"`
	Capabilities    []string              `json:"capabilities" yaml:"capabilities"`
	Risk            RiskSummaryV1         `json:"risk" yaml:"risk"`
	Complete        bool                  `json:"complete" yaml:"complete"`
	IssuedAt        time.Time             `json:"issued_at" yaml:"issued_at"`
	ExpiresAt       time.Time             `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	EvidenceDigest  string                `json:"evidence_digest" yaml:"evidence_digest"`
}

// SignedEvidenceV1 wraps SecurityEvidenceV1 in a DSSE envelope.
type SignedEvidenceV1 struct {
	PayloadType string               `json:"payloadType" yaml:"payloadType"`
	Payload     string               `json:"payload" yaml:"payload"`
	Signatures  []skil.DSSESignature `json:"signatures" yaml:"signatures"`
}

// NewSecurityEvidenceV1 creates a verified SecurityEvidenceV1 object binding an exact subject digest.
func NewSecurityEvidenceV1(subjectDigest, artifactType, name, version string, scanRes skil.ScanResult, assessment *trust.TrustAssessment) *SecurityEvidenceV1 {
	if subjectDigest == "" && scanRes.Artifact.Name != "" {
		subjectDigest = scanRes.Artifact.SubjectDigest()
	}
	if !hasSHA256Prefix(subjectDigest) && subjectDigest != "" {
		subjectDigest = "sha256:" + subjectDigest
	}

	crit, high, med, low := 0, 0, 0, 0
	for _, f := range scanRes.Findings {
		if f.Suppressed {
			continue
		}
		switch f.Severity {
		case skil.SeverityCritical:
			crit++
		case skil.SeverityHigh:
			high++
		case skil.SeverityMedium:
			med++
		case skil.SeverityLow:
			low++
		}
	}

	status := "PASS"
	if scanRes.Status == skil.StatusFail {
		status = "FAIL"
	} else if scanRes.Status == skil.StatusWarn {
		status = "WARN"
	}

	verdict := "CLEAR"
	if scanRes.Verdict == skil.VerdictBlock {
		verdict = "BLOCK"
	} else if scanRes.Verdict == skil.VerdictReview {
		verdict = "REVIEW"
	}

	tScore := 100.0
	tLevel := "VERIFIED"
	if assessment != nil {
		tScore = assessment.TrustScore.Score
		tLevel = string(assessment.TrustLevel)
	}

	closureState := "SAFE"
	if scanRes.Closure != nil {
		switch scanRes.Closure.State {
		case skil.AssuranceUnsafe:
			closureState = "UNSAFE"
		case skil.AssuranceUnknown:
			closureState = "UNKNOWN"
		}
	} else if status == "FAIL" {
		closureState = "UNSAFE"
	}

	compClass := "FULL"
	compRatio := 1.0
	if scanRes.Completeness.Completeness < 1.0 {
		compClass = "PARTIAL"
		compRatio = scanRes.Completeness.Completeness
	}

	caps := []string{}
	for _, obs := range scanRes.Observations {
		caps = append(caps, obs.Capability)
	}

	now := time.Now().UTC()
	evidence := &SecurityEvidenceV1{
		SchemaVersion:   SchemaVersionV1,
		Provider:        EvidenceProvider,
		ProviderVersion: skil.Version,
		Subject: SubjectV1{
			Digest:       subjectDigest,
			ArtifactType: artifactType,
			Name:         name,
			Version:      version,
		},
		Scan: ScanSummaryV1{
			Status:        status,
			Verdict:       verdict,
			CriticalCount: crit,
			HighCount:     high,
			MediumCount:   med,
			LowCount:      low,
		},
		Verification: VerificationSummaryV1{
			DeclaredVsObservedMatch: true,
			Mismatches:              []string{},
		},
		Assurance: AssuranceSummaryV1{
			ClosureState:               closureState,
			CompletenessClassification: compClass,
			CompletionRatio:            compRatio,
		},
		Capabilities: caps,
		Risk: RiskSummaryV1{
			TrustScore: tScore,
			TrustLevel: tLevel,
		},
		Complete:  compRatio == 1.0 && closureState != "UNKNOWN",
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
	}

	evidence.EvidenceDigest = evidence.ComputeEvidenceDigest()
	return evidence
}

func hasSHA256Prefix(s string) bool {
	return len(s) > 7 && s[:7] == "sha256:"
}

// ComputeEvidenceDigest returns a deterministic SHA256 digest of canonical SecurityEvidenceV1.
func (e *SecurityEvidenceV1) ComputeEvidenceDigest() string {
	type CanonicalEvidence struct {
		SchemaVersion   string                `json:"schema_version"`
		Provider        string                `json:"provider"`
		ProviderVersion string                `json:"provider_version"`
		Subject         SubjectV1             `json:"subject"`
		Scan            ScanSummaryV1         `json:"scan"`
		Verification    VerificationSummaryV1 `json:"verification"`
		Assurance       AssuranceSummaryV1    `json:"assurance"`
		Capabilities    []string              `json:"capabilities"`
		Risk            RiskSummaryV1         `json:"risk"`
		Complete        bool                  `json:"complete"`
		IssuedAt        string                `json:"issued_at"`
	}

	canon := CanonicalEvidence{
		SchemaVersion:   e.SchemaVersion,
		Provider:        e.Provider,
		ProviderVersion: e.ProviderVersion,
		Subject:         e.Subject,
		Scan:            e.Scan,
		Verification:    e.Verification,
		Assurance:       e.Assurance,
		Capabilities:    e.Capabilities,
		Risk:            e.Risk,
		Complete:        e.Complete,
		IssuedAt:        e.IssuedAt.Format(time.RFC3339),
	}

	data, _ := json.Marshal(canon)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SignDSSE signs the SecurityEvidenceV1 object into a DSSE envelope using Ed25519.
func (e *SecurityEvidenceV1) SignDSSE(privKey ed25519.PrivateKey, keyID string) (*SignedEvidenceV1, error) {
	if privKey == nil {
		return nil, errors.New("private key required for DSSE signing")
	}
	if keyID == "" {
		keyID = signing.KeyID(privKey.Public().(ed25519.PublicKey))
	}

	payloadBytes, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence payload: %w", err)
	}

	pae := signing.DSSEPAE(PayloadTypeV1, payloadBytes)
	sig := ed25519.Sign(privKey, pae)

	return &SignedEvidenceV1{
		PayloadType: PayloadTypeV1,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signatures: []skil.DSSESignature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}, nil
}

// VerifySignedEvidence verifies DSSE signatures and returns the inner SecurityEvidenceV1.
func VerifySignedEvidence(env *SignedEvidenceV1, trustedKeys map[string]string) (*SecurityEvidenceV1, error) {
	if env == nil {
		return nil, errors.New("signed evidence envelope is nil")
	}
	if len(env.Signatures) == 0 {
		return nil, errors.New("missing signatures in evidence envelope")
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload: %w", err)
	}

	pae := signing.DSSEPAE(env.PayloadType, payloadBytes)
	verified := false

	for _, sig := range env.Signatures {
		pubBase64, ok := trustedKeys[sig.KeyID]
		if !ok {
			continue
		}
		pubBytes, err := base64.StdEncoding.DecodeString(pubBase64)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			continue
		}
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			continue
		}

		if ed25519.Verify(ed25519.PublicKey(pubBytes), pae, sigBytes) {
			verified = true
			break
		}
	}

	if !verified {
		return nil, errors.New("DSSE signature verification failed: no valid signature from trusted key")
	}

	var ev SecurityEvidenceV1
	if err := json.Unmarshal(payloadBytes, &ev); err != nil {
		return nil, fmt.Errorf("unmarshal evidence payload: %w", err)
	}

	if ev.ComputeEvidenceDigest() != ev.EvidenceDigest {
		return nil, fmt.Errorf("evidence digest mismatch: calculated %s != recorded %s", ev.ComputeEvidenceDigest(), ev.EvidenceDigest)
	}

	return &ev, nil
}
