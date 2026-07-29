package skil

import (
	"encoding/json"
	"time"
)

type Evidence struct {
	Type             string             `json:"type" yaml:"type"`
	Producer         string             `json:"producer" yaml:"producer"`
	ProducerVer      string             `json:"producer_version" yaml:"producer_version"`
	SubjectDigest    string             `json:"subject_digest" yaml:"subject_digest"`
	Timestamp        time.Time          `json:"timestamp" yaml:"timestamp"`
	PayloadDigest    string             `json:"payload_digest,omitempty" yaml:"payload_digest,omitempty"`
	Result           EvidenceResult     `json:"result" yaml:"result"`
	Coverage         []string           `json:"coverage,omitempty" yaml:"coverage,omitempty"`
	Inspection       *InspectionSummary `json:"inspection_summary,omitempty" yaml:"inspection_summary,omitempty"`
	InspectionDigest string             `json:"inspection_ledger_sha256,omitempty" yaml:"inspection_ledger_sha256,omitempty"`
	Evaluation       *EvalEvidence      `json:"evaluation,omitempty" yaml:"evaluation,omitempty"`
}

type EvalEvidence struct {
	EvalSpecDigest string       `json:"eval_spec_digest" yaml:"eval_spec_digest"`
	Runtime        string       `json:"runtime" yaml:"runtime"`
	Coverage       EvalCoverage `json:"coverage" yaml:"coverage"`
	Metrics        EvalMetrics  `json:"metrics" yaml:"metrics"`
	Violations     int          `json:"containment_violations" yaml:"containment_violations"`
	Denied         int          `json:"denied_operations" yaml:"denied_operations"`
	SideEffects    int          `json:"forbidden_side_effects" yaml:"forbidden_side_effects"`
}

type EvidenceBundle struct {
	Version   int             `json:"version" yaml:"version"`
	Evidence  Evidence        `json:"evidence" yaml:"evidence"`
	Payload   json.RawMessage `json:"payload" yaml:"payload"`
	Signature *Signature      `json:"signature,omitempty" yaml:"signature,omitempty"`
}

type EvidenceResult struct {
	Status          Status   `json:"status" yaml:"status"`
	Verdict         Verdict  `json:"verdict,omitempty" yaml:"verdict,omitempty"`
	MaximumSeverity Severity `json:"maximum_severity" yaml:"maximum_severity"`
	RiskScore       int      `json:"risk_score,omitempty" yaml:"risk_score,omitempty"`
	Findings        int      `json:"findings" yaml:"findings"`
}

type Attestation struct {
	Version   int          `json:"version" yaml:"version"`
	Subject   Subject      `json:"subject" yaml:"subject"`
	Producer  Producer     `json:"producer" yaml:"producer"`
	Analysis  []string     `json:"analysis" yaml:"analysis"`
	Result    AttestResult `json:"result" yaml:"result"`
	Timestamp time.Time    `json:"timestamp" yaml:"timestamp"`
	Evidence  []Evidence   `json:"evidence" yaml:"evidence"`
	Signature *Signature   `json:"signature,omitempty" yaml:"signature,omitempty"`
}
type Subject struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	SHA256  string `json:"sha256" yaml:"sha256"`
}
type Producer struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}
type AttestResult struct {
	Status          Status   `json:"status" yaml:"status"`
	Verdict         Verdict  `json:"verdict,omitempty" yaml:"verdict,omitempty"`
	MaximumSeverity Severity `json:"maximum_severity" yaml:"maximum_severity"`
	RiskScore       int      `json:"risk_score" yaml:"risk_score"`
}
type Signature struct {
	Provider  string `json:"provider" yaml:"provider"`
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	KeyID     string `json:"key_id" yaml:"key_id"`
	Value     string `json:"value" yaml:"value"`
}

type PackageStatement struct {
	Version               int        `json:"version" yaml:"version"`
	Name                  string     `json:"name" yaml:"name"`
	VersionName           string     `json:"package_version" yaml:"package_version"`
	PackageSHA256         string     `json:"package_sha256" yaml:"package_sha256"`
	ContentManifestSHA256 string     `json:"content_manifest_sha256" yaml:"content_manifest_sha256"`
	Timestamp             time.Time  `json:"timestamp" yaml:"timestamp"`
	Signature             *Signature `json:"signature,omitempty" yaml:"signature,omitempty"`
}

type DSSESignature struct {
	KeyID string `json:"keyid" yaml:"keyid"`
	Sig   string `json:"sig" yaml:"sig"`
}

type Provenance struct {
	PayloadType string          `json:"payloadType" yaml:"payloadType"`
	Payload     string          `json:"payload" yaml:"payload"`
	Signatures  []DSSESignature `json:"signatures" yaml:"signatures"`
}

type InTotoStatement struct {
	Type          string          `json:"_type"`
	Subject       []InTotoSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     SLSAPredicate   `json:"predicate"`
}

type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type SLSAPredicate struct {
	BuildDefinition SLSABuildDefinition `json:"buildDefinition"`
	RunDetails      SLSARunDetails      `json:"runDetails"`
}

type SLSABuildDefinition struct {
	BuildType            string            `json:"buildType"`
	ExternalParameters   map[string]string `json:"externalParameters"`
	InternalParameters   map[string]string `json:"internalParameters,omitempty"`
	ResolvedDependencies []SLSAResource    `json:"resolvedDependencies"`
}

type SLSAResource struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type SLSARunDetails struct {
	Builder  SLSABuilder  `json:"builder"`
	Metadata SLSAMetadata `json:"metadata"`
}

type SLSABuilder struct {
	ID string `json:"id"`
}

type SLSAMetadata struct {
	InvocationID string    `json:"invocationId,omitempty"`
	StartedOn    time.Time `json:"startedOn"`
	FinishedOn   time.Time `json:"finishedOn"`
}
