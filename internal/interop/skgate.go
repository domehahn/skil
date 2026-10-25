package interop

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/domehahn/skil/internal/evidence"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

type AdmissionDecision string

const (
	DecisionAllow    AdmissionDecision = "ALLOW"
	DecisionDeny     AdmissionDecision = "DENY"
	DecisionReview   AdmissionDecision = "REVIEW"
	DecisionReassess AdmissionDecision = "REASSESS"
)

type AdmissionPolicy struct {
	RequireSignedEvidence bool          `json:"require_signed_evidence"`
	MaxEvidenceAge        time.Duration `json:"max_evidence_age"`
	RequireSafeClosure    bool          `json:"require_safe_closure"`
	MinTrustScore         float64       `json:"min_trust_score"`
	AllowedSigners        []string      `json:"allowed_signers"`
}

func DefaultAdmissionPolicy() AdmissionPolicy {
	return AdmissionPolicy{
		RequireSignedEvidence: true,
		MaxEvidenceAge:        24 * time.Hour,
		RequireSafeClosure:    true,
		MinTrustScore:         75.0,
		AllowedSigners:        []string{},
	}
}

type SKGateAdmissionEvaluator struct {
	Policy      AdmissionPolicy
	TrustedKeys map[string]string // KeyID -> Public Key Base64
}

type AdmissionResult struct {
	Decision       AdmissionDecision `json:"decision"`
	Reason         string            `json:"reason"`
	ArtifactDigest string            `json:"artifact_digest"`
	EvidenceDigest string            `json:"evidence_digest"`
	SignerKeyID    string            `json:"signer_key_id"`
	Timestamp      time.Time         `json:"timestamp"`
}

// EvaluateAdmission performs cryptographic verification and admission policy evaluation on a signed SKIL evidence envelope.
func (e *SKGateAdmissionEvaluator) EvaluateAdmission(targetSubjectDigest string, signedEv *evidence.SignedEvidenceV1) AdmissionResult {
	now := time.Now().UTC()

	if signedEv == nil {
		return AdmissionResult{
			Decision:  DecisionDeny,
			Reason:    "signed evidence envelope is missing",
			Timestamp: now,
		}
	}

	ev, err := evidence.VerifySignedEvidence(signedEv, e.TrustedKeys)
	if err != nil {
		return AdmissionResult{
			Decision:  DecisionDeny,
			Reason:    fmt.Sprintf("cryptographic signature verification failed: %v", err),
			Timestamp: now,
		}
	}

	signerKeyID := ""
	if len(signedEv.Signatures) > 0 {
		signerKeyID = signedEv.Signatures[0].KeyID
	}

	// 1. Exact subject digest binding
	if targetSubjectDigest != "" && ev.Subject.Digest != targetSubjectDigest {
		return AdmissionResult{
			Decision:       DecisionReassess,
			Reason:         fmt.Sprintf("subject digest mismatch: requested %s != evidence subject %s", targetSubjectDigest, ev.Subject.Digest),
			ArtifactDigest: ev.Subject.Digest,
			EvidenceDigest: ev.EvidenceDigest,
			SignerKeyID:    signerKeyID,
			Timestamp:      now,
		}
	}

	// 2. Allowed signers restriction
	if len(e.Policy.AllowedSigners) > 0 {
		allowed := false
		for _, s := range e.Policy.AllowedSigners {
			if s == signerKeyID {
				allowed = true
				break
			}
		}
		if !allowed {
			return AdmissionResult{
				Decision:       DecisionDeny,
				Reason:         fmt.Sprintf("signer key %s is not in organizational allowed signers list", signerKeyID),
				ArtifactDigest: ev.Subject.Digest,
				EvidenceDigest: ev.EvidenceDigest,
				SignerKeyID:    signerKeyID,
				Timestamp:      now,
			}
		}
	}

	// 3. Stale evidence check
	if e.Policy.MaxEvidenceAge > 0 && now.Sub(ev.IssuedAt) > e.Policy.MaxEvidenceAge {
		return AdmissionResult{
			Decision:       DecisionReassess,
			Reason:         fmt.Sprintf("evidence is stale: issued at %s exceeded max age %s", ev.IssuedAt.Format(time.RFC3339), e.Policy.MaxEvidenceAge),
			ArtifactDigest: ev.Subject.Digest,
			EvidenceDigest: ev.EvidenceDigest,
			SignerKeyID:    signerKeyID,
			Timestamp:      now,
		}
	}

	// 4. Expiration check
	if !ev.ExpiresAt.IsZero() && now.After(ev.ExpiresAt) {
		return AdmissionResult{
			Decision:       DecisionReassess,
			Reason:         fmt.Sprintf("evidence expired at %s", ev.ExpiresAt.Format(time.RFC3339)),
			ArtifactDigest: ev.Subject.Digest,
			EvidenceDigest: ev.EvidenceDigest,
			SignerKeyID:    signerKeyID,
			Timestamp:      now,
		}
	}

	// 5. Completeness check
	if !ev.Complete {
		return AdmissionResult{
			Decision:       DecisionDeny,
			Reason:         "scan evidence is incomplete",
			ArtifactDigest: ev.Subject.Digest,
			EvidenceDigest: ev.EvidenceDigest,
			SignerKeyID:    signerKeyID,
			Timestamp:      now,
		}
	}

	// 6. Security scan verdict & closure evaluation
	if ev.Scan.Verdict == "BLOCK" || ev.Assurance.ClosureState == "UNSAFE" {
		return AdmissionResult{
			Decision:       DecisionDeny,
			Reason:         fmt.Sprintf("security scan block (verdict=%s, closure=%s)", ev.Scan.Verdict, ev.Assurance.ClosureState),
			ArtifactDigest: ev.Subject.Digest,
			EvidenceDigest: ev.EvidenceDigest,
			SignerKeyID:    signerKeyID,
			Timestamp:      now,
		}
	}

	if e.Policy.RequireSafeClosure && ev.Assurance.ClosureState != "SAFE" {
		return AdmissionResult{
			Decision:       DecisionDeny,
			Reason:         fmt.Sprintf("assurance closure state %s is not SAFE", ev.Assurance.ClosureState),
			ArtifactDigest: ev.Subject.Digest,
			EvidenceDigest: ev.EvidenceDigest,
			SignerKeyID:    signerKeyID,
			Timestamp:      now,
		}
	}

	if ev.Risk.TrustScore < e.Policy.MinTrustScore {
		return AdmissionResult{
			Decision:       DecisionReview,
			Reason:         fmt.Sprintf("trust score %.1f below minimum required %.1f", ev.Risk.TrustScore, e.Policy.MinTrustScore),
			ArtifactDigest: ev.Subject.Digest,
			EvidenceDigest: ev.EvidenceDigest,
			SignerKeyID:    signerKeyID,
			Timestamp:      now,
		}
	}

	if ev.Scan.Verdict == "REVIEW" {
		return AdmissionResult{
			Decision:       DecisionReview,
			Reason:         "security scan returned REVIEW verdict",
			ArtifactDigest: ev.Subject.Digest,
			EvidenceDigest: ev.EvidenceDigest,
			SignerKeyID:    signerKeyID,
			Timestamp:      now,
		}
	}

	return AdmissionResult{
		Decision:       DecisionAllow,
		Reason:         "cryptographic verification and admission policy satisfied",
		ArtifactDigest: ev.Subject.Digest,
		EvidenceDigest: ev.EvidenceDigest,
		SignerKeyID:    signerKeyID,
		Timestamp:      now,
	}
}

// GenerateSignedTestEvidence is a helper to build signed evidence for interop testing.
func GenerateSignedTestEvidence(privKey ed25519.PrivateKey, subjectDigest string, verdict string, score float64) (*evidence.SignedEvidenceV1, error) {
	keyID := signing.KeyID(privKey.Public().(ed25519.PublicKey))
	scanRes := skil.ScanResult{
		Status:  skil.StatusPass,
		Verdict: skil.VerdictClear,
		Completeness: skil.InspectionSummary{
			Total: 1, Applicable: 1, Completed: 1,
			Completeness: 1.0,
		},
		Closure: &skil.AssuranceClosure{RootDigest: subjectDigest, Digest: "sha256:test-closure", Complete: true, Verified: true, State: skil.AssuranceSafe},
	}
	if verdict == "BLOCK" {
		scanRes.Status = skil.StatusFail
		scanRes.Verdict = skil.VerdictBlock
	} else if verdict == "REVIEW" {
		scanRes.Verdict = skil.VerdictReview
	}

	ev := evidence.NewSecurityEvidenceV1(subjectDigest, "compiled-skill", "interop-test-skill", "1.0.0", scanRes, nil)
	ev.Risk.TrustScore = score
	ev.EvidenceDigest = ev.ComputeEvidenceDigest()
	return ev.SignDSSE(privKey, keyID)
}
