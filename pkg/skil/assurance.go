package skil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AssuranceStage is a proof transition, not a progress label. A required
// control is complete only when every required stage has non-empty evidence.
type AssuranceStage string

const (
	StageExpected                  AssuranceStage = "EXPECTED"
	StageLoaded                    AssuranceStage = "LOADED"
	StageRegistered                AssuranceStage = "REGISTERED"
	StageScheduled                 AssuranceStage = "SCHEDULED"
	StageInvocationBuilt           AssuranceStage = "INVOCATION_BUILT"
	StageDestinationResolved       AssuranceStage = "DESTINATION_RESOLVED"
	StageRequestAccepted           AssuranceStage = "REQUEST_ACCEPTED"
	StageResponseReceived          AssuranceStage = "RESPONSE_RECEIVED"
	StageResponseContractValidated AssuranceStage = "RESPONSE_CONTRACT_VALIDATED"
	StageEvidenceProduced          AssuranceStage = "EVIDENCE_PRODUCED"
	StageEvidenceCommitted         AssuranceStage = "EVIDENCE_COMMITTED"
	StageDecisionConsumed          AssuranceStage = "DECISION_CONSUMED"
	StageProofPersisted            AssuranceStage = "PROOF_PERSISTED"
)

var DefaultAssuranceStages = []AssuranceStage{
	StageExpected, StageLoaded, StageRegistered, StageScheduled,
	StageInvocationBuilt, StageDestinationResolved, StageRequestAccepted,
	StageResponseReceived, StageResponseContractValidated, StageEvidenceProduced,
	StageEvidenceCommitted, StageDecisionConsumed, StageProofPersisted,
}

type AssuranceEvidence struct {
	Stage      AssuranceStage `json:"stage"`
	EvidenceID string         `json:"evidence_id"`
	Digest     string         `json:"digest"`
	Timestamp  time.Time      `json:"timestamp"`
	Detail     string         `json:"detail,omitempty"`
}

type ControlProof struct {
	ControlID      string              `json:"control_id"`
	Analyzer       string              `json:"analyzer"`
	SubjectDigest  string              `json:"subject_digest"`
	RequiredStages []AssuranceStage    `json:"required_stages"`
	Evidence       []AssuranceEvidence `json:"evidence,omitempty"`
	Required       bool                `json:"required"`
	Complete       bool                `json:"complete"`
	Limitation     string              `json:"limitation,omitempty"`
}

func (p ControlProof) Validate() error {
	if p.ControlID == "" || p.SubjectDigest == "" || !p.Required {
		return errors.New("required control proof needs control and subject identity")
	}
	want := map[AssuranceStage]bool{}
	for _, stage := range p.RequiredStages {
		want[stage] = true
	}
	seen := map[AssuranceStage]bool{}
	for _, e := range p.Evidence {
		if e.Stage == "" || e.EvidenceID == "" || e.Digest == "" {
			return errors.New("assurance evidence is incomplete")
		}
		seen[e.Stage] = true
	}
	for stage := range want {
		if !seen[stage] {
			return fmt.Errorf("required control %q lacks proof for %s", p.ControlID, stage)
		}
	}
	return nil
}

type AssuranceDimension string

const (
	DimensionArtifactInspection     AssuranceDimension = "ArtifactInspection"
	DimensionReferenceResolution    AssuranceDimension = "ReferenceResolution"
	DimensionControlExecution       AssuranceDimension = "ControlExecution"
	DimensionSemanticInterpretation AssuranceDimension = "SemanticInterpretation"
	DimensionRuntimeVerification    AssuranceDimension = "RuntimeVerification"
	DimensionIdentityResolution     AssuranceDimension = "IdentityResolution"
	DimensionAuthorityResolution    AssuranceDimension = "AuthorityResolution"
	DimensionProviderExecution      AssuranceDimension = "ProviderExecution"
	DimensionEvidenceIntegrity      AssuranceDimension = "EvidenceIntegrity"
)

type DimensionState string

const (
	DimensionComplete      DimensionState = "COMPLETE"
	DimensionPartial       DimensionState = "PARTIAL"
	DimensionFailed        DimensionState = "FAILED"
	DimensionUnknown       DimensionState = "UNKNOWN"
	DimensionNotApplicable DimensionState = "NOT_APPLICABLE"
)

type AssuranceDimensionResult struct {
	Dimension   AssuranceDimension `json:"dimension"`
	State       DimensionState     `json:"state"`
	Evidence    []string           `json:"evidence,omitempty"`
	Limitations []string           `json:"limitations,omitempty"`
}

type AssuranceLimitation struct {
	Subject        string               `json:"subject"`
	Phase          string               `json:"phase"`
	Cause          string               `json:"cause"`
	Dimensions     []AssuranceDimension `json:"dimensions"`
	Evidence       []string             `json:"evidence,omitempty"`
	Analyzer       string               `json:"analyzer,omitempty"`
	Control        string               `json:"control,omitempty"`
	DecisionEffect string               `json:"decision_effect"`
}

type AssuranceOutcome string

const (
	OutcomeComplete         AssuranceOutcome = "COMPLETE"
	OutcomePartial          AssuranceOutcome = "PARTIAL"
	OutcomeFailed           AssuranceOutcome = "FAILED"
	OutcomeNotApplicable    AssuranceOutcome = "NOT_APPLICABLE"
	OutcomeExcludedByPolicy AssuranceOutcome = "EXCLUDED_BY_POLICY"
)

type AssuranceOutcomeProof struct {
	Outcome               AssuranceOutcome `json:"outcome"`
	Evidence              []string         `json:"evidence"`
	PolicyID              string           `json:"policy_id,omitempty"`
	ApplicabilityEvidence string           `json:"applicability_evidence,omitempty"`
	Unresolved            []string         `json:"unresolved,omitempty"`
}

func (p AssuranceOutcomeProof) Validate() error {
	if p.Outcome == "" {
		return errors.New("assurance outcome is required")
	}
	if len(p.Evidence) == 0 {
		return errors.New("assurance outcome requires evidence")
	}
	switch p.Outcome {
	case OutcomeComplete:
		if len(p.Unresolved) != 0 {
			return errors.New("complete outcome has unresolved properties")
		}
	case OutcomePartial, OutcomeFailed:
		if len(p.Unresolved) == 0 {
			return errors.New("partial or failed outcome needs unresolved evidence")
		}
	case OutcomeNotApplicable:
		if p.ApplicabilityEvidence == "" {
			return errors.New("not-applicable outcome needs applicability proof")
		}
	case OutcomeExcludedByPolicy:
		if p.PolicyID == "" {
			return errors.New("policy exclusion needs policy identity")
		}
	default:
		return fmt.Errorf("unknown assurance outcome %q", p.Outcome)
	}
	return nil
}

type AssuranceReport struct {
	Outcome        AssuranceOutcome           `json:"outcome"`
	Controls       []ControlProof             `json:"controls,omitempty"`
	Dimensions     []AssuranceDimensionResult `json:"dimensions,omitempty"`
	Limitations    []AssuranceLimitation      `json:"limitations,omitempty"`
	EvidenceDigest string                     `json:"evidence_digest"`
	Proof          AssuranceOutcomeProof      `json:"proof"`
}

// VerificationDestinationBinding contains only non-secret identity. It is
// deliberately impossible to validate a binding with an empty or ambient
// endpoint, and redirects are never represented as an accepted destination.
type VerificationDestinationBinding struct {
	AuthorizedProvider       string `json:"authorized_provider"`
	AuthorizedEndpoint       string `json:"authorized_endpoint"`
	EffectiveProvider        string `json:"effective_provider"`
	EffectiveEndpoint        string `json:"effective_endpoint"`
	CredentialScope          string `json:"credential_scope"`
	ModelIdentity            string `json:"model_identity"`
	RequestConfigDigest      string `json:"request_config_digest"`
	EvidenceProjectionDigest string `json:"evidence_projection_digest"`
	Redirected               bool   `json:"redirected"`
}

func (b VerificationDestinationBinding) Validate() error {
	if b.AuthorizedProvider == "" || b.EffectiveProvider == "" || b.CredentialScope == "" || b.ModelIdentity == "" || b.RequestConfigDigest == "" || b.EvidenceProjectionDigest == "" {
		return errors.New("destination binding is incomplete")
	}
	for name, value := range map[string]string{"authorized_endpoint": b.AuthorizedEndpoint, "effective_endpoint": b.EffectiveEndpoint} {
		u, err := url.Parse(value)
		if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if b.Redirected || !sameEndpoint(b.AuthorizedEndpoint, b.EffectiveEndpoint) || b.AuthorizedProvider != b.EffectiveProvider {
		return errors.New("effective verification destination is not authorized")
	}
	return nil
}

func sameEndpoint(a, b string) bool {
	ua, ea := url.Parse(a)
	ub, eb := url.Parse(b)
	return ea == nil && eb == nil && strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host) && ua.EscapedPath() == ub.EscapedPath() && ua.RawQuery == ub.RawQuery
}

type EffectiveInvocationEvidence struct {
	InvocationID            string                         `json:"invocation_id"`
	RequestedConfigDigest   string                         `json:"requested_config_digest"`
	ResolvedConfigDigest    string                         `json:"resolved_config_digest"`
	TransmittedConfigDigest string                         `json:"transmitted_config_digest"`
	AcceptedConfigDigest    string                         `json:"accepted_config_digest"`
	ResponseSemanticsDigest string                         `json:"response_semantics_digest"`
	Deviations              []string                       `json:"deviations,omitempty"`
	Destination             VerificationDestinationBinding `json:"destination"`
}

func (e EffectiveInvocationEvidence) Validate() error {
	if e.InvocationID == "" || e.RequestedConfigDigest == "" || e.ResolvedConfigDigest == "" || e.TransmittedConfigDigest == "" || e.AcceptedConfigDigest == "" || e.ResponseSemanticsDigest == "" {
		return errors.New("invocation evidence is incomplete")
	}
	if err := e.Destination.Validate(); err != nil {
		return err
	}
	if len(e.Deviations) > 0 {
		return fmt.Errorf("assurance-relevant invocation deviation: %s", strings.Join(e.Deviations, "; "))
	}
	return nil
}

type CoverageDisposition string

const (
	CoverageDiscovered       CoverageDisposition = "DISCOVERED"
	CoverageOmitted          CoverageDisposition = "OMITTED"
	CoverageUnsupported      CoverageDisposition = "UNSUPPORTED"
	CoverageFailed           CoverageDisposition = "FAILED"
	CoverageBudgetLimited    CoverageDisposition = "BUDGET_LIMITED"
	CoverageExcludedByPolicy CoverageDisposition = "EXCLUDED_BY_POLICY"
)

type CoverageSubject struct {
	ID, PhysicalDigest, Source, Owner string
	Disposition                       CoverageDisposition
	Required                          bool
	Evidence                          []string `json:"evidence,omitempty"`
}
type CoverageUniverse struct {
	Subjects []CoverageSubject `json:"subjects"`
}

func (u CoverageUniverse) Complete() bool {
	for _, s := range u.Subjects {
		if s.Required && s.Disposition != CoverageDiscovered && s.Disposition != CoverageExcludedByPolicy {
			return false
		}
	}
	return len(u.Subjects) > 0
}

// SubjectOwnershipGraph prevents overlapping discovery from creating a second
// security subject. Ownership is digest-based, deterministic, and only hides a
// descendant when the owner actually completed analysis.
type SubjectOwnershipGraph struct {
	Owners map[string]string `json:"owners"`
	Failed map[string]bool   `json:"failed,omitempty"`
}

func (g *SubjectOwnershipGraph) Claim(physicalDigest, owner string, ownerSucceeded bool) string {
	if g.Owners == nil {
		g.Owners = map[string]string{}
	}
	if current := g.Owners[physicalDigest]; current != "" && !g.Failed[current] {
		return current
	}
	if ownerSucceeded {
		g.Owners[physicalDigest] = owner
		return owner
	}
	g.Failed[owner] = true
	return ""
}

type FindingIdentity struct {
	RuleID      string `json:"rule_id"`
	ClassDigest string `json:"class_digest"`
}
type FindingOccurrenceIdentity struct {
	FindingIdentity
	SubjectDigest  string `json:"subject_digest"`
	Path           string `json:"path"`
	StartLine      int    `json:"start_line"`
	EndLine        int    `json:"end_line"`
	ArtifactDigest string `json:"artifact_digest"`
	Fingerprint    string `json:"fingerprint"`
}

func NewFindingOccurrenceIdentity(ruleID, classDigest, subjectDigest, path string, start, end int, artifactDigest string) FindingOccurrenceIdentity {
	o := FindingOccurrenceIdentity{FindingIdentity: FindingIdentity{RuleID: ruleID, ClassDigest: classDigest}, SubjectDigest: subjectDigest, Path: path, StartLine: start, EndLine: end, ArtifactDigest: artifactDigest}
	b, _ := json.Marshal(o)
	sum := sha256.Sum256(b)
	o.Fingerprint = "sha256:" + hex.EncodeToString(sum[:])
	return o
}

type BaselineTargetKind string

const (
	BaselineFindingClass BaselineTargetKind = "FINDING_CLASS"
	BaselineOccurrence   BaselineTargetKind = "OCCURRENCE"
	BaselineSubject      BaselineTargetKind = "SUBJECT"
	BaselineArtifact     BaselineTargetKind = "DIGEST_BOUND_ARTIFACT"
)

type BaselineTarget struct {
	Kind           BaselineTargetKind `json:"kind"`
	Identity       string             `json:"identity"`
	SubjectDigest  string             `json:"subject_digest,omitempty"`
	ArtifactDigest string             `json:"artifact_digest,omitempty"`
}

type RuleMaturity string

const (
	RuleExperimental        RuleMaturity = "EXPERIMENTAL"
	RuleObserve             RuleMaturity = "OBSERVE"
	RuleBenchmarked         RuleMaturity = "BENCHMARKED"
	RuleDecisionEligible    RuleMaturity = "DECISION_ELIGIBLE"
	RuleEnforcementEligible RuleMaturity = "ENFORCEMENT_ELIGIBLE"
)

type AnalyzerAttribution struct {
	CorpusDigest, SampleID, AnalyzerID, AnalyzerVersion, RuleID, FindingID, OccurrenceID, ExpectedLabel, ActualDecision, DecisionEffect string
	Maturity                                                                                                                            RuleMaturity `json:"maturity"`
}

func (a AnalyzerAttribution) Validate() error {
	if a.CorpusDigest == "" || a.SampleID == "" || a.AnalyzerID == "" || a.RuleID == "" || a.OccurrenceID == "" || a.Maturity == "" {
		return errors.New("benchmark attribution is incomplete")
	}
	return nil
}

func DigestJSON(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func SortDimensions(d []AssuranceDimensionResult) {
	sort.Slice(d, func(i, j int) bool { return d[i].Dimension < d[j].Dimension })
}
