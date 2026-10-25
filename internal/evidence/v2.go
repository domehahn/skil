package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const SchemaVersionV2 = "2.0"

type ModelIdentityV2 struct {
	Provider            string  `json:"provider"`
	Endpoint            string  `json:"endpoint,omitempty"`
	RequestedModel      string  `json:"requested_model"`
	ReportedModel       string  `json:"reported_model,omitempty"`
	ObservedFingerprint string  `json:"observed_fingerprint,omitempty"`
	FingerprintMethod   string  `json:"fingerprint_method,omitempty"`
	BaselineIdentity    string  `json:"baseline_identity,omitempty"`
	Confidence          float64 `json:"confidence"`
}

type AttestationInputsV2 struct {
	SubjectIdentity               string           `json:"subject_identity"`
	ClosureDigest                 string           `json:"closure_digest"`
	PolicyDigest                  string           `json:"policy_digest"`
	EvidenceGraphDigest           string           `json:"evidence_graph_digest"`
	ObserverDigest                string           `json:"observer_digest"`
	AnalysisPlanDigest            string           `json:"analysis_plan_digest"`
	WorkLedgerDigest              string           `json:"work_ledger_digest"`
	BudgetPolicyDigest            string           `json:"budget_policy_digest"`
	AnalysisCompleteness          string           `json:"analysis_completeness"`
	ResolutionCompleteness        string           `json:"resolution_completeness"`
	DiscoveryCompleteness         string           `json:"discovery_completeness"`
	AuthorizationConstraintDigest string           `json:"authorization_constraint_digest"`
	EffectiveAuthorityDigest      string           `json:"effective_authority_digest"`
	BehavioralSuiteDigest         string           `json:"behavioral_suite_digest,omitempty"`
	RuntimeEvidenceDigest         string           `json:"runtime_evidence_digest,omitempty"`
	LossOfControlDigest           string           `json:"loss_of_control_digest,omitempty"`
	ModelIdentity                 *ModelIdentityV2 `json:"model_identity,omitempty"`
	FinalDecision                 string           `json:"final_decision"`
}

type AttestationV2 struct {
	SchemaVersion string              `json:"schema_version"`
	Inputs        AttestationInputsV2 `json:"inputs"`
	Digest        string              `json:"digest"`
}

func NewAttestationV2(inputs AttestationInputsV2) (AttestationV2, error) {
	required := []string{inputs.SubjectIdentity, inputs.ClosureDigest, inputs.PolicyDigest, inputs.EvidenceGraphDigest, inputs.ObserverDigest, inputs.AnalysisPlanDigest, inputs.WorkLedgerDigest, inputs.BudgetPolicyDigest, inputs.AnalysisCompleteness, inputs.ResolutionCompleteness, inputs.DiscoveryCompleteness, inputs.AuthorizationConstraintDigest, inputs.EffectiveAuthorityDigest, inputs.FinalDecision}
	for _, value := range required {
		if value == "" {
			return AttestationV2{}, errors.New("attestation v2 cannot bind an unbacked required field")
		}
	}
	if inputs.ModelIdentity != nil && (inputs.ModelIdentity.Provider == "" || inputs.ModelIdentity.RequestedModel == "") {
		return AttestationV2{}, errors.New("model identity requires provider and requested model")
	}
	a := AttestationV2{SchemaVersion: SchemaVersionV2, Inputs: inputs}
	a.Digest = a.ComputeDigest()
	return a, nil
}

func (a AttestationV2) ComputeDigest() string {
	a.Digest = ""
	b, _ := json.Marshal(a)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (a AttestationV2) Verify() error {
	if a.SchemaVersion != SchemaVersionV2 || a.Digest == "" || a.Digest != a.ComputeDigest() {
		return errors.New("attestation v2 identity mismatch")
	}
	return nil
}
