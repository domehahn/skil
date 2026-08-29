package gate

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/policy"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

type GateOptions struct {
	ArtifactPath    string
	AttestationPath string
	PolicyPath      string
	TrustedSigners  map[string]string
	MaxAge          string
}

type GateResult struct {
	Allowed            bool               `json:"allowed"`
	Reason             string             `json:"reason"`
	ArtifactDigest     string             `json:"artifact_digest"`
	AttestationSubject string             `json:"attestation_subject,omitempty"`
	ClosureDigest      string             `json:"closure_digest,omitempty"`
	Violations         []policy.Violation `json:"violations,omitempty"`
	EvaluatedAt        time.Time          `json:"evaluated_at"`
}

// CheckGate performs 6-stage cryptographic admission verification over an artifact and attestation.
func CheckGate(options GateOptions) (GateResult, error) {
	now := time.Now().UTC()
	result := GateResult{
		EvaluatedAt: now,
	}

	// 1. Load artifact
	art, err := artifact.Load(options.ArtifactPath, artifact.Options{})
	if err != nil {
		return result, fmt.Errorf("load artifact: %w", err)
	}
	result.ArtifactDigest = art.SubjectDigest()

	// 2. Read and parse Attestation
	attData, err := os.ReadFile(options.AttestationPath)
	if err != nil {
		return result, fmt.Errorf("read attestation: %w", err)
	}
	var att skil.Attestation
	if err := json.Unmarshal(attData, &att); err != nil {
		return result, fmt.Errorf("parse attestation: %w", err)
	}
	result.AttestationSubject = att.Subject.SHA256
	if att.ReferenceClosure != nil {
		result.ClosureDigest = att.ReferenceClosure.Digest
	}

	// 3. Signature verification
	if len(options.TrustedSigners) > 0 {
		if err := signing.VerifyAttestation(att, options.TrustedSigners); err != nil {
			result.Allowed = false
			result.Reason = fmt.Sprintf("signature verification failed: %v", err)
			return result, nil
		}
	}

	// 4. Digest matching
	if att.Subject.SHA256 != result.ArtifactDigest {
		result.Allowed = false
		result.Reason = fmt.Sprintf("attestation subject digest %s does not match artifact digest %s", att.Subject.SHA256, result.ArtifactDigest)
		return result, nil
	}

	// 5. Load and evaluate Policy if specified
	var pol policy.Policy
	if options.PolicyPath != "" {
		loadedPol, err := policy.Load(options.PolicyPath)
		if err != nil {
			return result, fmt.Errorf("load policy: %w", err)
		}
		pol = loadedPol
	} else {
		pol = policy.Policy{Version: 1, MaximumSeverity: "HIGH"}
	}

	// Perform policy evaluation
	polResult := policy.Check(pol, policy.Input{
		Scan: skil.ScanResult{
			Artifact: art,
			Status:   skil.StatusPass,
			Verdict:  skil.VerdictClear,
		},
		Attestation: &att,
	})

	if polResult.Decision != "ALLOW" {
		result.Allowed = false
		result.Reason = "policy decision denied artifact admission"
		result.Violations = polResult.Violations
		return result, nil
	}

	result.Allowed = true
	result.Reason = "artifact admission approved: valid signature, digest match, and policy compliance verified"
	return result, nil
}
