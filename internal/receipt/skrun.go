package receipt

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
	"github.com/domehahn/skil/pkg/skil"
)

const (
	ReceiptVersionV1     = "1.0"
	PayloadTypeReceiptV1 = "application/vnd.skrun.receipt.v1+json"
)

type IsolationSummary struct {
	NativeIsolationActive bool   `json:"native_isolation_active" yaml:"native_isolation_active"`
	SandboxMode           string `json:"sandbox_mode" yaml:"sandbox_mode"`
	SeccompProfile        string `json:"seccomp_profile,omitempty" yaml:"seccomp_profile,omitempty"`
	NetworkSandboxed      bool   `json:"network_sandboxed" yaml:"network_sandboxed"`
}

type ResourceUsageSummary struct {
	DurationMS     int64 `json:"duration_ms" yaml:"duration_ms"`
	MaxMemoryBytes int64 `json:"max_memory_bytes" yaml:"max_memory_bytes"`
	CPUTimeMS      int64 `json:"cpu_time_ms" yaml:"cpu_time_ms"`
}

// SKRunReceiptV1 represents a cryptographic execution receipt emitted by skrun.
type SKRunReceiptV1 struct {
	ReceiptVersion string               `json:"receipt_version" yaml:"receipt_version"`
	ExecutionID    string               `json:"execution_id" yaml:"execution_id"`
	RuntimeBackend string               `json:"runtime_backend" yaml:"runtime_backend"`
	SubjectDigest  string               `json:"subject_digest" yaml:"subject_digest"`
	PolicyDigest   string               `json:"policy_digest" yaml:"policy_digest"`
	Status         string               `json:"status" yaml:"status"` // SUCCESS, CONTAINED_DENIAL, RUNTIME_ERROR, BUDGET_EXCEEDED
	DeniedActions  []string             `json:"denied_actions,omitempty" yaml:"denied_actions,omitempty"`
	Isolation      IsolationSummary     `json:"isolation" yaml:"isolation"`
	ResourceUsage  ResourceUsageSummary `json:"resource_usage" yaml:"resource_usage"`
	IssuedAt       time.Time            `json:"issued_at" yaml:"issued_at"`
	Signatures     []skil.DSSESignature `json:"signatures" yaml:"signatures"`
}

type VerificationOptions struct {
	ExpectedSubjectDigest  string
	ExpectedPolicyDigest   string
	RequireNativeIsolation bool
	TrustedKeys            map[string]string // KeyID -> Public Key Base64
}

type VerificationResult struct {
	Valid          bool      `json:"valid"`
	ExecutionID    string    `json:"execution_id"`
	SubjectDigest  string    `json:"subject_digest"`
	RuntimeBackend string    `json:"runtime_backend"`
	Reason         string    `json:"reason"`
	VerifiedAt     time.Time `json:"verified_at"`
}

// ComputePayloadDigest returns the canonical SHA256 digest of the receipt payload without signatures.
func (r *SKRunReceiptV1) ComputePayloadDigest() string {
	type CanonicalPayload struct {
		ReceiptVersion string               `json:"receipt_version"`
		ExecutionID    string               `json:"execution_id"`
		RuntimeBackend string               `json:"runtime_backend"`
		SubjectDigest  string               `json:"subject_digest"`
		PolicyDigest   string               `json:"policy_digest"`
		Status         string               `json:"status"`
		DeniedActions  []string             `json:"denied_actions,omitempty"`
		Isolation      IsolationSummary     `json:"isolation"`
		ResourceUsage  ResourceUsageSummary `json:"resource_usage"`
		IssuedAt       string               `json:"issued_at"`
	}

	canon := CanonicalPayload{
		ReceiptVersion: r.ReceiptVersion,
		ExecutionID:    r.ExecutionID,
		RuntimeBackend: r.RuntimeBackend,
		SubjectDigest:  r.SubjectDigest,
		PolicyDigest:   r.PolicyDigest,
		Status:         r.Status,
		DeniedActions:  r.DeniedActions,
		Isolation:      r.Isolation,
		ResourceUsage:  r.ResourceUsage,
		IssuedAt:       r.IssuedAt.Format(time.RFC3339),
	}

	data, _ := json.Marshal(canon)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SignReceipt signs the SKRunReceiptV1 using Ed25519 DSSE PAE.
func (r *SKRunReceiptV1) SignReceipt(privKey ed25519.PrivateKey, keyID string) error {
	if privKey == nil {
		return errors.New("private key is required to sign receipt")
	}
	if keyID == "" {
		keyID = signing.KeyID(privKey.Public().(ed25519.PublicKey))
	}

	canonDigest := r.ComputePayloadDigest()
	pae := signing.DSSEPAE(PayloadTypeReceiptV1, []byte(canonDigest))
	sig := ed25519.Sign(privKey, pae)

	r.Signatures = []skil.DSSESignature{
		{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(sig),
		},
	}
	return nil
}

// VerifyReceipt cryptographically verifies a skrun receipt against expectations and trusted keys.
func VerifyReceipt(receipt *SKRunReceiptV1, opts VerificationOptions) VerificationResult {
	now := time.Now().UTC()

	if receipt == nil {
		return VerificationResult{Valid: false, Reason: "receipt is nil", VerifiedAt: now}
	}

	if len(receipt.Signatures) == 0 {
		return VerificationResult{
			Valid:          false,
			ExecutionID:    receipt.ExecutionID,
			SubjectDigest:  receipt.SubjectDigest,
			RuntimeBackend: receipt.RuntimeBackend,
			Reason:         "missing cryptographic signatures on receipt",
			VerifiedAt:     now,
		}
	}

	// 1. Signature Verification
	canonDigest := receipt.ComputePayloadDigest()
	pae := signing.DSSEPAE(PayloadTypeReceiptV1, []byte(canonDigest))
	verified := false

	for _, sig := range receipt.Signatures {
		pubBase64, ok := opts.TrustedKeys[sig.KeyID]
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

	if !verified && len(opts.TrustedKeys) > 0 {
		return VerificationResult{
			Valid:          false,
			ExecutionID:    receipt.ExecutionID,
			SubjectDigest:  receipt.SubjectDigest,
			RuntimeBackend: receipt.RuntimeBackend,
			Reason:         "signature verification failed against trusted key set",
			VerifiedAt:     now,
		}
	}

	// 2. Subject Digest Verification
	if opts.ExpectedSubjectDigest != "" && receipt.SubjectDigest != opts.ExpectedSubjectDigest {
		return VerificationResult{
			Valid:          false,
			ExecutionID:    receipt.ExecutionID,
			SubjectDigest:  receipt.SubjectDigest,
			RuntimeBackend: receipt.RuntimeBackend,
			Reason:         fmt.Sprintf("subject digest mismatch: expected %s != receipt %s", opts.ExpectedSubjectDigest, receipt.SubjectDigest),
			VerifiedAt:     now,
		}
	}

	// 3. Policy Digest Verification
	if opts.ExpectedPolicyDigest != "" && receipt.PolicyDigest != opts.ExpectedPolicyDigest {
		return VerificationResult{
			Valid:          false,
			ExecutionID:    receipt.ExecutionID,
			SubjectDigest:  receipt.SubjectDigest,
			RuntimeBackend: receipt.RuntimeBackend,
			Reason:         fmt.Sprintf("policy digest mismatch: expected %s != receipt %s", opts.ExpectedPolicyDigest, receipt.PolicyDigest),
			VerifiedAt:     now,
		}
	}

	// 4. Native Isolation Requirement
	if opts.RequireNativeIsolation && !receipt.Isolation.NativeIsolationActive {
		return VerificationResult{
			Valid:          false,
			ExecutionID:    receipt.ExecutionID,
			SubjectDigest:  receipt.SubjectDigest,
			RuntimeBackend: receipt.RuntimeBackend,
			Reason:         "required native isolation was not active during execution",
			VerifiedAt:     now,
		}
	}

	// 5. Execution Status Check
	if receipt.Status == "RUNTIME_ERROR" || receipt.Status == "BUDGET_EXCEEDED" {
		return VerificationResult{
			Valid:          false,
			ExecutionID:    receipt.ExecutionID,
			SubjectDigest:  receipt.SubjectDigest,
			RuntimeBackend: receipt.RuntimeBackend,
			Reason:         fmt.Sprintf("execution ended with status %s", receipt.Status),
			VerifiedAt:     now,
		}
	}

	return VerificationResult{
		Valid:          true,
		ExecutionID:    receipt.ExecutionID,
		SubjectDigest:  receipt.SubjectDigest,
		RuntimeBackend: receipt.RuntimeBackend,
		Reason:         "skrun execution receipt verified successfully",
		VerifiedAt:     now,
	}
}
