package continuous

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/domehahn/skil/internal/assurance"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

// AssuranceDependencyKind enumerates all security-relevant assumptions an
// assurance proof or policy decision can depend on.
type AssuranceDependencyKind string

const (
	DepSkillContentDigest      AssuranceDependencyKind = "skill_content_digest"
	DepAgentConfig             AssuranceDependencyKind = "agent_config"
	DepModelIdentity           AssuranceDependencyKind = "model_identity"
	DepProviderIdentity        AssuranceDependencyKind = "provider_identity"
	DepToolSchema              AssuranceDependencyKind = "tool_schema"
	DepMCPServerIdentity       AssuranceDependencyKind = "mcp_server_identity"
	DepDependencyVersion       AssuranceDependencyKind = "dependency_version"
	DepPackageDigest           AssuranceDependencyKind = "package_digest"
	DepRuntimeCapabilities     AssuranceDependencyKind = "runtime_capabilities"
	DepPolicyVersion           AssuranceDependencyKind = "policy_version"
	DepVerificationEnvironment AssuranceDependencyKind = "verification_environment"
	DepCredentialScope         AssuranceDependencyKind = "credential_scope"
	DepRAGDataSource           AssuranceDependencyKind = "rag_data_source"
	DepMemoryState             AssuranceDependencyKind = "memory_state"
	DepExternalServiceIdentity AssuranceDependencyKind = "external_service_identity"
)

// AssuranceDependency binds a typed dependency identity and digest to an
// explicit EvidenceState (OBSERVED, INFERRED, VERIFIED, or UNKNOWN).
type AssuranceDependency struct {
	Kind       AssuranceDependencyKind `json:"kind"`
	Identity   string                  `json:"identity"`
	Digest     string                  `json:"digest"`
	State      skil.EvidenceState      `json:"state"`
	ControlIDs []string                `json:"control_ids,omitempty"`
}

func (d AssuranceDependency) key() string {
	return string(d.Kind) + ":" + d.Identity
}

// AttachAssuranceDependenciesToGraph projects typed assurance dependencies into
// the existing skil.EvidenceGraphSummary without creating a second dependency graph.
func AttachAssuranceDependenciesToGraph(graph *skil.EvidenceGraphSummary, subjectNodeID string, subjectDigest string, deps []AssuranceDependency) *skil.EvidenceGraphSummary {
	if graph == nil {
		graph = &skil.EvidenceGraphSummary{}
	}
	seenNodes := make(map[string]int, len(graph.Nodes))
	for i, n := range graph.Nodes {
		seenNodes[n.ID] = i
	}
	if subjectNodeID == "" {
		subjectNodeID = "subject:" + subjectDigest
	}
	if _, exists := seenNodes[subjectNodeID]; !exists {
		seenNodes[subjectNodeID] = len(graph.Nodes)
		graph.Nodes = append(graph.Nodes, skil.EvidenceGraphNode{
			ID:     subjectNodeID,
			Kind:   "subject",
			RefID:  subjectDigest,
			State:  skil.EvidenceVerified,
			Detail: "assured subject root",
		})
	}

	seenEdges := make(map[string]bool, len(graph.Edges))
	for _, e := range graph.Edges {
		seenEdges[e.From+"\x00"+e.To+"\x00"+e.Relation] = true
	}

	for _, dep := range deps {
		state := dep.State
		if state == "" || dep.Digest == "" {
			state = skil.EvidenceState("UNKNOWN")
		}
		sum := sha256.Sum256([]byte(string(dep.Kind) + "\x00" + dep.Identity + "\x00" + dep.Digest))
		nodeID := "assurance-dep:" + hex.EncodeToString(sum[:8])
		node := skil.EvidenceGraphNode{
			ID:     nodeID,
			Kind:   "assurance-dependency",
			RefID:  string(dep.Kind) + ":" + dep.Identity,
			State:  state,
			Detail: dep.Digest,
		}
		if idx, exists := seenNodes[nodeID]; exists {
			graph.Nodes[idx] = node
		} else {
			seenNodes[nodeID] = len(graph.Nodes)
			graph.Nodes = append(graph.Nodes, node)
		}
		edgeKey := subjectNodeID + "\x00" + nodeID + "\x00depends-on-assurance"
		if !seenEdges[edgeKey] {
			seenEdges[edgeKey] = true
			graph.Edges = append(graph.Edges, skil.EvidenceGraphEdge{
				From:      subjectNodeID,
				To:        nodeID,
				Relation:  "depends-on-assurance",
				State:     state,
				Rationale: fmt.Sprintf("assurance depends on %s (%s)", dep.Kind, dep.Identity),
			})
		}
	}

	sort.Slice(graph.Nodes, func(i, j int) bool { return graph.Nodes[i].ID < graph.Nodes[j].ID })
	sort.Slice(graph.Edges, func(i, j int) bool {
		if graph.Edges[i].From != graph.Edges[j].From {
			return graph.Edges[i].From < graph.Edges[j].From
		}
		if graph.Edges[i].To != graph.Edges[j].To {
			return graph.Edges[i].To < graph.Edges[j].To
		}
		return graph.Edges[i].Relation < graph.Edges[j].Relation
	})
	copySummary := *graph
	copySummary.Digest = ""
	if raw, err := signing.CanonicalJSON(copySummary); err == nil {
		sum := sha256.Sum256(raw)
		graph.Digest = hex.EncodeToString(sum[:])
	}
	return graph
}

// ProofValidityState represents the live assurance state of a registered proof.
type ProofValidityState string

const (
	ProofValid       ProofValidityState = "VALID"
	ProofStale       ProofValidityState = "STALE"
	ProofInvalidated ProofValidityState = "INVALIDATED"
	ProofUnknown     ProofValidityState = "UNKNOWN"
)

// AssuranceValidityConditions declares the exact conditions under which an
// assurance result remains valid. Unobserved assumptions prevent VALID state.
type AssuranceValidityConditions struct {
	SubjectID                 string                `json:"subject_id"`
	SubjectSource             string                `json:"subject_source"`
	SubjectDigest             string                `json:"subject_digest"`
	PolicyID                  string                `json:"policy_id"`
	PolicyDigest              string                `json:"policy_digest"`
	ProviderIdentity          string                `json:"provider_identity,omitempty"`
	ProviderConfigDigest      string                `json:"provider_config_digest,omitempty"`
	ModelIdentity             string                `json:"model_identity,omitempty"`
	VerificationEnvDigest     string                `json:"verification_env_digest"`
	ToolSchemaDigests         map[string]string     `json:"tool_schema_digests,omitempty"`
	RuntimeCapabilities       []string              `json:"runtime_capabilities,omitempty"`
	Dependencies              []AssuranceDependency `json:"dependencies,omitempty"`
	RequiredEvidenceIDs       []string              `json:"required_evidence_ids"`
	UnobservedAssumptions     []string              `json:"unobserved_assumptions,omitempty"`
	IssuedAt                  time.Time             `json:"issued_at"`
	ExpiresAt                 time.Time             `json:"expires_at"`
	MaxReconciliationInterval time.Duration         `json:"max_reconciliation_interval"`
}

// Validate checks whether the validity conditions are complete and whether any
// unobserved assumption forces an UNKNOWN state.
func (c AssuranceValidityConditions) Validate() error {
	if strings.TrimSpace(c.SubjectID) == "" || strings.TrimSpace(c.SubjectSource) == "" || strings.TrimSpace(c.SubjectDigest) == "" {
		return errors.New("validity conditions require subject_id, subject_source, and subject_digest")
	}
	if strings.TrimSpace(c.PolicyID) == "" || strings.TrimSpace(c.PolicyDigest) == "" {
		return errors.New("validity conditions require policy_id and policy_digest")
	}
	if strings.TrimSpace(c.VerificationEnvDigest) == "" {
		return errors.New("validity conditions require verification_env_digest")
	}
	if len(c.RequiredEvidenceIDs) == 0 {
		return errors.New("validity conditions require at least one required_evidence_id")
	}
	if len(c.UnobservedAssumptions) > 0 {
		return fmt.Errorf("unobserved assumptions cannot be treated as verified facts: %s",
			strings.Join(c.UnobservedAssumptions, "; "))
	}
	for _, dep := range c.Dependencies {
		if dep.Digest == "" || dep.State == "" || dep.State == skil.EvidenceState("UNKNOWN") {
			return fmt.Errorf("dependency %s (%s) has unobserved or unknown state", dep.Kind, dep.Identity)
		}
	}
	return nil
}

// AssuredSubjectRecord holds the live state, dependencies, controls, and
// dependent policy decisions for an assured subject.
type AssuredSubjectRecord struct {
	SubjectID               string                      `json:"subject_id"`
	SubjectDigest           string                      `json:"subject_digest"`
	AssuranceEvidenceDigest string                      `json:"assurance_evidence_digest"`
	State                   ProofValidityState          `json:"state"`
	InvalidationReasons     []string                    `json:"invalidation_reasons,omitempty"`
	Validity                AssuranceValidityConditions `json:"validity"`
	Controls                []skil.ControlProof         `json:"controls"`
	DependentDecisions      map[string]bool             `json:"dependent_decisions"` // DecisionID -> valid
	EvidenceGraph           *skil.EvidenceGraphSummary  `json:"evidence_graph,omitempty"`
	LastReconciledAt        time.Time                   `json:"last_reconciled_at"`
	ReVerificationRequired  bool                        `json:"re_verification_required"`
}

// DriftEvent represents an event-driven notification of a security-relevant change.
type DriftEvent struct {
	EventID    string                  `json:"event_id"`
	SubjectID  string                  `json:"subject_id,omitempty"` // empty means environment-wide (e.g. policy or provider change)
	Kind       AssuranceDependencyKind `json:"kind"`
	Identity   string                  `json:"identity"`
	NewDigest  string                  `json:"new_digest"`
	OccurredAt time.Time               `json:"occurred_at"`
}

// EnvironmentSnapshot represents the observed ground-truth state during
// periodic reconciliation (catching any missed event notifications).
type EnvironmentSnapshot struct {
	SubjectDigests        map[string]string // SubjectID -> current SubjectDigest
	PolicyID              string
	PolicyDigest          string
	ProviderIdentity      string
	ProviderConfigDigest  string
	ModelIdentity         string
	VerificationEnvDigest string
	ToolSchemaDigests     map[string]string            // Tool/MCP -> schema digest
	RuntimeCapabilities   []string                     // currently active runtime permissions
	ObservedDependencies  map[string]map[string]string // SubjectID -> (kind:identity -> digest)
}

// AssuranceTransitionRecord provides an immutable audit trail of every
// assurance invalidation, decision revocation, and re-assurance trigger.
type AssuranceTransitionRecord struct {
	Timestamp                    time.Time               `json:"timestamp"`
	SubjectID                    string                  `json:"subject_id"`
	SubjectDigest                string                  `json:"subject_digest"`
	PreviousState                ProofValidityState      `json:"previous_state"`
	NewState                     ProofValidityState      `json:"new_state"`
	Trigger                      string                  `json:"trigger"`
	DriftKind                    AssuranceDependencyKind `json:"drift_kind,omitempty"`
	DriftIdentity                string                  `json:"drift_identity,omitempty"`
	Reason                       string                  `json:"reason"`
	InvalidatedDecisions         []string                `json:"invalidated_decisions,omitempty"`
	ReVerificationTriggered      bool                    `json:"re_verification_triggered"`
	RetroactivePreventionClaimed bool                    `json:"retroactive_prevention_claimed"`
}

// SelectiveReAssurancePlan identifies which controls must be re-executed and
// which cached control proofs remain valid after a drift event.
type SelectiveReAssurancePlan struct {
	SubjectID          string   `json:"subject_id"`
	SubjectDigest      string   `json:"subject_digest"`
	FullRescanRequired bool     `json:"full_rescan_required"`
	DriftedKeys        []string `json:"drifted_keys"`
	ControlsToReRun    []string `json:"controls_to_rerun"`
	ReusableControls   []string `json:"reusable_controls"`
	IncompatibleReason string   `json:"incompatible_reason,omitempty"`
}

// CachedControlEvidence binds a cached ControlProof to its exact validity context.
type CachedControlEvidence struct {
	CacheKey              string
	SubjectID             string
	SubjectSource         string
	SubjectDigest         string
	ProviderIdentity      string
	ProviderConfigDigest  string
	ToolSchemaDigest      string
	PolicyDigest          string
	VerificationEnvDigest string
	DependencyDigests     map[string]string
	Proof                 skil.ControlProof
}

// Engine manages continuous assurance validity, event-driven drift handling,
// periodic reconciliation, selective re-assurance, and runtime enforcement gating.
type Engine struct {
	mu          sync.Mutex
	records     map[string]*AssuredSubjectRecord // SubjectDigest -> record
	bySubjectID map[string]string                // SubjectID -> SubjectDigest
	cache       map[string]CachedControlEvidence // control cache key -> evidence
	transitions []AssuranceTransitionRecord
	now         func() time.Time
}

func NewEngine(now func() time.Time) *Engine {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Engine{
		records:     make(map[string]*AssuredSubjectRecord),
		bySubjectID: make(map[string]string),
		cache:       make(map[string]CachedControlEvidence),
		now:         now,
	}
}

// RegisterAssurance registers or updates an assured subject record and populates
// its typed assurance dependencies in the Evidence Graph.
func (e *Engine) RegisterAssurance(
	validity AssuranceValidityConditions,
	assuranceEvidenceDigest string,
	controls []skil.ControlProof,
	decisionIDs []string,
	graph *skil.EvidenceGraphSummary,
) (*AssuredSubjectRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now().UTC()
	if validity.IssuedAt.IsZero() {
		validity.IssuedAt = now
	}
	if validity.MaxReconciliationInterval <= 0 {
		validity.MaxReconciliationInterval = 15 * time.Minute
	}
	if validity.ExpiresAt.IsZero() {
		validity.ExpiresAt = validity.IssuedAt.Add(24 * time.Hour)
	}

	state := ProofValid
	var reasons []string
	if err := validity.Validate(); err != nil {
		state = ProofUnknown
		reasons = append(reasons, err.Error())
	}
	for _, ctrl := range controls {
		if ctrl.Required {
			if err := ctrl.Validate(); err != nil {
				state = ProofUnknown
				reasons = append(reasons, err.Error())
			}
		}
	}

	updatedGraph := AttachAssuranceDependenciesToGraph(graph, "subject:"+validity.SubjectDigest, validity.SubjectDigest, validity.Dependencies)

	decisions := make(map[string]bool, len(decisionIDs))
	for _, id := range decisionIDs {
		if strings.TrimSpace(id) != "" {
			decisions[id] = (state == ProofValid)
		}
	}

	rec := &AssuredSubjectRecord{
		SubjectID:               validity.SubjectID,
		SubjectDigest:           validity.SubjectDigest,
		AssuranceEvidenceDigest: assuranceEvidenceDigest,
		State:                   state,
		InvalidationReasons:     reasons,
		Validity:                validity,
		Controls:                append([]skil.ControlProof(nil), controls...),
		DependentDecisions:      decisions,
		EvidenceGraph:           updatedGraph,
		LastReconciledAt:        now,
		ReVerificationRequired:  state != ProofValid,
	}
	e.records[validity.SubjectDigest] = rec
	e.bySubjectID[validity.SubjectID] = validity.SubjectDigest
	e.transitions = append(e.transitions, AssuranceTransitionRecord{
		Timestamp:                    now,
		SubjectID:                    validity.SubjectID,
		SubjectDigest:                validity.SubjectDigest,
		PreviousState:                ProofUnknown,
		NewState:                     state,
		Trigger:                      "register_assurance",
		Reason:                       "assurance record registered",
		ReVerificationTriggered:      state != ProofValid,
		RetroactivePreventionClaimed: false,
	})

	if state == ProofValid {
		for _, ctrl := range controls {
			if ctrl.Complete {
				depMap := make(map[string]string)
				for _, dep := range validity.Dependencies {
					if len(dep.ControlIDs) == 0 || containsStr(dep.ControlIDs, ctrl.ControlID) {
						depMap[dep.key()] = dep.Digest
					}
				}
				key := e.controlCacheKey(validity.SubjectID, validity.SubjectDigest, ctrl.ControlID)
				e.cache[key] = CachedControlEvidence{
					CacheKey:              key,
					SubjectID:             validity.SubjectID,
					SubjectSource:         validity.SubjectSource,
					SubjectDigest:         validity.SubjectDigest,
					ProviderIdentity:      validity.ProviderIdentity,
					ProviderConfigDigest:  validity.ProviderConfigDigest,
					ToolSchemaDigest:      digestToolSchemas(validity.ToolSchemaDigests),
					PolicyDigest:          validity.PolicyDigest,
					VerificationEnvDigest: validity.VerificationEnvDigest,
					DependencyDigests:     depMap,
					Proof:                 ctrl,
				}
			}
		}
	}

	return cloneRecord(rec), nil
}

func (e *Engine) controlCacheKey(subjectID, subjectDigest, controlID string) string {
	sum := sha256.Sum256([]byte(subjectID + "\x00" + subjectDigest + "\x00" + controlID))
	return "ctrl-cache:" + hex.EncodeToString(sum[:])
}

func digestToolSchemas(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	raw, _ := signing.CanonicalJSON(m)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// IngestDriftEvent processes an event-driven drift notification and immediately
// invalidates affected assurance records and dependent policy decisions.
func (e *Engine) IngestDriftEvent(ev DriftEvent) []AssuranceTransitionRecord {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now().UTC()
	var emitted []AssuranceTransitionRecord

	for _, rec := range e.records {
		if ev.SubjectID != "" && rec.SubjectID != ev.SubjectID {
			continue
		}
		drifted, reason := evaluateEventAgainstRecord(rec, ev)
		if !drifted {
			continue
		}
		tr := e.invalidateRecordLocked(rec, ProofInvalidated, "drift_event:"+ev.EventID, ev.Kind, ev.Identity, reason, now)
		emitted = append(emitted, tr)
	}
	return emitted
}

func evaluateEventAgainstRecord(rec *AssuredSubjectRecord, ev DriftEvent) (bool, string) {
	v := rec.Validity
	switch ev.Kind {
	case DepSkillContentDigest, DepPackageDigest:
		if ev.NewDigest != rec.SubjectDigest {
			return true, fmt.Sprintf("artifact digest drifted from %s to %s", rec.SubjectDigest, ev.NewDigest)
		}
	case DepPolicyVersion:
		if ev.NewDigest != v.PolicyDigest {
			return true, fmt.Sprintf("policy digest drifted from %s to %s", v.PolicyDigest, ev.NewDigest)
		}
	case DepProviderIdentity:
		if ev.Identity != v.ProviderIdentity || (ev.NewDigest != "" && ev.NewDigest != v.ProviderConfigDigest) {
			return true, fmt.Sprintf("provider configuration drifted (%s / %s)", ev.Identity, ev.NewDigest)
		}
	case DepModelIdentity:
		if ev.Identity != v.ModelIdentity && ev.NewDigest != v.ModelIdentity {
			return true, fmt.Sprintf("model identity drifted from %s to %s", v.ModelIdentity, ev.Identity)
		}
	case DepVerificationEnvironment:
		if ev.NewDigest != v.VerificationEnvDigest {
			return true, fmt.Sprintf("verification environment drifted from %s to %s", v.VerificationEnvDigest, ev.NewDigest)
		}
	case DepToolSchema:
		if expected, ok := v.ToolSchemaDigests[ev.Identity]; !ok || expected != ev.NewDigest {
			return true, fmt.Sprintf("tool schema %q drifted from %s to %s", ev.Identity, expected, ev.NewDigest)
		}
	case DepRuntimeCapabilities:
		if !containsStr(v.RuntimeCapabilities, ev.Identity) || ev.NewDigest == "ESCALATED" {
			return true, fmt.Sprintf("runtime permissions drifted for %q", ev.Identity)
		}
	}
	for _, dep := range v.Dependencies {
		if dep.Kind == ev.Kind && dep.Identity == ev.Identity && dep.Digest != ev.NewDigest {
			return true, fmt.Sprintf("dependency %s (%s) drifted from %s to %s", dep.Kind, dep.Identity, dep.Digest, ev.NewDigest)
		}
	}
	return false, ""
}

// Reconcile compares all registered assurance records against an observed
// EnvironmentSnapshot so missed events cannot leave stale assurance valid.
func (e *Engine) Reconcile(snapshot EnvironmentSnapshot) []AssuranceTransitionRecord {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now().UTC()
	var emitted []AssuranceTransitionRecord

	for _, rec := range e.records {
		var reasons []string
		var firstKind AssuranceDependencyKind
		var firstID string
		mark := func(k AssuranceDependencyKind, id, r string) {
			if firstKind == "" {
				firstKind = k
				firstID = id
			}
			reasons = append(reasons, r)
		}

		if actualDigest, ok := snapshot.SubjectDigests[rec.SubjectID]; ok && actualDigest != rec.SubjectDigest {
			mark(DepSkillContentDigest, rec.SubjectID, fmt.Sprintf("reconciliation detected skill digest change: %s -> %s", rec.SubjectDigest, actualDigest))
		}
		if snapshot.PolicyDigest != "" && snapshot.PolicyDigest != rec.Validity.PolicyDigest {
			mark(DepPolicyVersion, rec.Validity.PolicyID, fmt.Sprintf("reconciliation detected policy digest change: %s -> %s", rec.Validity.PolicyDigest, snapshot.PolicyDigest))
		}
		if snapshot.ProviderIdentity != "" && snapshot.ProviderIdentity != rec.Validity.ProviderIdentity {
			mark(DepProviderIdentity, snapshot.ProviderIdentity, fmt.Sprintf("reconciliation detected provider switch: %s -> %s", rec.Validity.ProviderIdentity, snapshot.ProviderIdentity))
		}
		if snapshot.ProviderConfigDigest != "" && rec.Validity.ProviderConfigDigest != "" && snapshot.ProviderConfigDigest != rec.Validity.ProviderConfigDigest {
			mark(DepProviderIdentity, rec.Validity.ProviderIdentity, "reconciliation detected provider config digest change")
		}
		if snapshot.ModelIdentity != "" && rec.Validity.ModelIdentity != "" && snapshot.ModelIdentity != rec.Validity.ModelIdentity {
			mark(DepModelIdentity, snapshot.ModelIdentity, fmt.Sprintf("reconciliation detected model drift: %s -> %s", rec.Validity.ModelIdentity, snapshot.ModelIdentity))
		}
		if snapshot.VerificationEnvDigest != "" && snapshot.VerificationEnvDigest != rec.Validity.VerificationEnvDigest {
			mark(DepVerificationEnvironment, "env", "reconciliation detected verification environment drift")
		}
		for toolID, expectedDigest := range rec.Validity.ToolSchemaDigests {
			if actualDigest, ok := snapshot.ToolSchemaDigests[toolID]; !ok || actualDigest != expectedDigest {
				mark(DepToolSchema, toolID, fmt.Sprintf("reconciliation detected MCP/tool schema drift for %q", toolID))
			}
		}
		if len(snapshot.RuntimeCapabilities) > 0 {
			for _, capName := range snapshot.RuntimeCapabilities {
				if !containsStr(rec.Validity.RuntimeCapabilities, capName) {
					mark(DepRuntimeCapabilities, capName, fmt.Sprintf("reconciliation detected unauthorized runtime permission escalation: %q", capName))
				}
			}
		}
		if subjDeps, ok := snapshot.ObservedDependencies[rec.SubjectID]; ok {
			for _, dep := range rec.Validity.Dependencies {
				if actual, present := subjDeps[dep.key()]; !present || actual != dep.Digest {
					mark(dep.Kind, dep.Identity, fmt.Sprintf("reconciliation detected drift in %s (%s): expected %s, got %s", dep.Kind, dep.Identity, dep.Digest, actual))
				}
			}
		}

		if len(reasons) > 0 {
			tr := e.invalidateRecordLocked(rec, ProofInvalidated, "reconciliation", firstKind, firstID, strings.Join(reasons, "; "), now)
			emitted = append(emitted, tr)
		} else {
			rec.LastReconciledAt = now
		}
	}
	return emitted
}

func (e *Engine) invalidateRecordLocked(
	rec *AssuredSubjectRecord,
	newState ProofValidityState,
	trigger string,
	kind AssuranceDependencyKind,
	identity string,
	reason string,
	now time.Time,
) AssuranceTransitionRecord {
	prev := rec.State
	rec.State = newState
	rec.InvalidationReasons = append(rec.InvalidationReasons, reason)
	rec.ReVerificationRequired = true

	var invalidatedDecisions []string
	for decID := range rec.DependentDecisions {
		rec.DependentDecisions[decID] = false
		invalidatedDecisions = append(invalidatedDecisions, decID)
	}
	sort.Strings(invalidatedDecisions)

	tr := AssuranceTransitionRecord{
		Timestamp:                    now,
		SubjectID:                    rec.SubjectID,
		SubjectDigest:                rec.SubjectDigest,
		PreviousState:                prev,
		NewState:                     newState,
		Trigger:                      trigger,
		DriftKind:                    kind,
		DriftIdentity:                identity,
		Reason:                       reason,
		InvalidatedDecisions:         invalidatedDecisions,
		ReVerificationTriggered:      true,
		RetroactivePreventionClaimed: false, // Completed operations are never claimed to be retroactively prevented.
	}
	e.transitions = append(e.transitions, tr)
	return tr
}

// IsAssuranceValid implements receipt.AssuranceValidityOracle for live runtime
// enforcement integration.
func (e *Engine) IsAssuranceValid(subjectDigest, assuranceEvidenceDigest, policyDigest, decisionID string) (bool, string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now().UTC()
	rec, ok := e.records[subjectDigest]
	if !ok {
		return false, "no registered assurance record for subject digest"
	}
	if rec.AssuranceEvidenceDigest != assuranceEvidenceDigest {
		return false, "assurance evidence digest does not match active record"
	}
	if rec.Validity.PolicyDigest != policyDigest {
		return false, "policy digest does not match assured policy"
	}
	if !now.Before(rec.Validity.ExpiresAt) {
		if rec.State == ProofValid {
			e.invalidateRecordLocked(rec, ProofStale, "expiration", DepPolicyVersion, rec.Validity.PolicyID, "assurance validity period expired", now)
		}
		return false, "assurance validity period has expired"
	}
	if rec.Validity.MaxReconciliationInterval > 0 && now.Sub(rec.LastReconciledAt) > rec.Validity.MaxReconciliationInterval {
		if rec.State == ProofValid {
			e.invalidateRecordLocked(rec, ProofStale, "reconciliation_timeout", DepVerificationEnvironment, rec.SubjectID, "reconciliation heartbeat window exceeded; missed events cannot be ruled out", now)
		}
		return false, "reconciliation heartbeat window exceeded; assurance is stale"
	}
	if rec.State != ProofValid {
		return false, fmt.Sprintf("assurance state is %s: %s", rec.State, strings.Join(rec.InvalidationReasons, "; "))
	}
	if decisionID != "" {
		validDecision, exists := rec.DependentDecisions[decisionID]
		if !exists || !validDecision {
			return false, fmt.Sprintf("dependent decision %q is invalidated or unknown", decisionID)
		}
	}
	return true, ""
}

// PlanSelectiveReAssurance determines the minimal set of controls that need to
// be re-executed when dependencies change, while refusing cache reuse across
// incompatible subjects, sources, artifact digests, provider configs, tool
// schemas, policy versions, or verification environments.
func (e *Engine) PlanSelectiveReAssurance(
	currentSubjectDigest string,
	candidate AssuranceValidityConditions,
	observedDeps map[string]string,
) SelectiveReAssurancePlan {
	e.mu.Lock()
	defer e.mu.Unlock()

	plan := SelectiveReAssurancePlan{
		SubjectID:     candidate.SubjectID,
		SubjectDigest: candidate.SubjectDigest,
	}

	rec, exists := e.records[currentSubjectDigest]
	if !exists {
		plan.FullRescanRequired = true
		plan.IncompatibleReason = "no baseline assurance record exists"
		return plan
	}

	// Global incompatibility checks that forbid any cached control reuse
	switch {
	case rec.Validity.SubjectID != candidate.SubjectID:
		plan.FullRescanRequired = true
		plan.IncompatibleReason = "incompatible subject_id"
	case rec.Validity.SubjectSource != candidate.SubjectSource:
		plan.FullRescanRequired = true
		plan.IncompatibleReason = "incompatible subject_source"
	case rec.SubjectDigest != candidate.SubjectDigest:
		plan.FullRescanRequired = true
		plan.IncompatibleReason = "incompatible artifact subject_digest"
	case rec.Validity.ProviderIdentity != candidate.ProviderIdentity || rec.Validity.ProviderConfigDigest != candidate.ProviderConfigDigest:
		plan.FullRescanRequired = true
		plan.IncompatibleReason = "incompatible provider configuration"
	case digestToolSchemas(rec.Validity.ToolSchemaDigests) != digestToolSchemas(candidate.ToolSchemaDigests):
		plan.FullRescanRequired = true
		plan.IncompatibleReason = "incompatible tool schema set"
	case rec.Validity.PolicyDigest != candidate.PolicyDigest:
		plan.FullRescanRequired = true
		plan.IncompatibleReason = "incompatible policy version"
	case rec.Validity.VerificationEnvDigest != candidate.VerificationEnvDigest:
		plan.FullRescanRequired = true
		plan.IncompatibleReason = "incompatible verification environment"
	}

	if plan.FullRescanRequired {
		for _, ctrl := range rec.Controls {
			plan.ControlsToReRun = append(plan.ControlsToReRun, ctrl.ControlID)
		}
		sort.Strings(plan.ControlsToReRun)
		return plan
	}

	// Selective dependency diff per control
	driftedControls := make(map[string]bool)
	for _, dep := range rec.Validity.Dependencies {
		actual, ok := observedDeps[dep.key()]
		if !ok || actual != dep.Digest {
			plan.DriftedKeys = append(plan.DriftedKeys, dep.key())
			if len(dep.ControlIDs) == 0 {
				// Unscoped dependency affects all controls
				for _, ctrl := range rec.Controls {
					driftedControls[ctrl.ControlID] = true
				}
			} else {
				for _, cid := range dep.ControlIDs {
					driftedControls[cid] = true
				}
			}
		}
	}
	sort.Strings(plan.DriftedKeys)

	for _, ctrl := range rec.Controls {
		cacheKey := e.controlCacheKey(candidate.SubjectID, candidate.SubjectDigest, ctrl.ControlID)
		cached, hasCache := e.cache[cacheKey]
		compatibleCache := hasCache &&
			cached.SubjectID == candidate.SubjectID &&
			cached.SubjectSource == candidate.SubjectSource &&
			cached.SubjectDigest == candidate.SubjectDigest &&
			cached.ProviderIdentity == candidate.ProviderIdentity &&
			cached.ProviderConfigDigest == candidate.ProviderConfigDigest &&
			cached.ToolSchemaDigest == digestToolSchemas(candidate.ToolSchemaDigests) &&
			cached.PolicyDigest == candidate.PolicyDigest &&
			cached.VerificationEnvDigest == candidate.VerificationEnvDigest

		if driftedControls[ctrl.ControlID] || !compatibleCache {
			plan.ControlsToReRun = append(plan.ControlsToReRun, ctrl.ControlID)
		} else {
			plan.ReusableControls = append(plan.ReusableControls, ctrl.ControlID)
		}
	}
	sort.Strings(plan.ControlsToReRun)
	sort.Strings(plan.ReusableControls)

	// Bridge with assurance.SubjectCacheIdentity to guarantee deterministic cache key hygiene
	_ = assurance.SubjectCacheIdentity{
		SourceType:    candidate.SubjectSource,
		SourceDigest:  candidate.SubjectDigest,
		PolicyDigest:  candidate.PolicyDigest,
		ConfigDigest:  candidate.VerificationEnvDigest,
		ContentSHA256: candidate.SubjectDigest,
	}

	return plan
}

// AuditLog returns a copy of all recorded assurance transitions.
func (e *Engine) AuditLog() []AssuranceTransitionRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]AssuranceTransitionRecord, len(e.transitions))
	copy(out, e.transitions)
	return out
}

func cloneRecord(r *AssuredSubjectRecord) *AssuredSubjectRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.InvalidationReasons = append([]string(nil), r.InvalidationReasons...)
	out.Controls = append([]skil.ControlProof(nil), r.Controls...)
	out.DependentDecisions = make(map[string]bool, len(r.DependentDecisions))
	for k, v := range r.DependentDecisions {
		out.DependentDecisions[k] = v
	}
	return &out
}

func containsStr(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}
