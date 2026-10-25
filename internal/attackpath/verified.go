package attackpath

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/domehahn/skil/internal/eval"
	"github.com/domehahn/skil/internal/receipt"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

// Extended multi-agent entity types (reusing NodeType in package attackpath).
const (
	NodeAgent              NodeType = "AGENT"
	NodeSubagent           NodeType = "SUBAGENT"
	NodeCredential         NodeType = "CREDENTIAL"
	NodeExternalEndpoint   NodeType = "EXTERNAL_ENDPOINT"
	NodeRAGSource          NodeType = "RAG_SOURCE"
	NodeMemoryStore        NodeType = "MEMORY_STORE"
	NodePolicy             NodeType = "POLICY"
	NodeRuntimeEnvironment NodeType = "RUNTIME_ENVIRONMENT"
	NodeAuthorization      NodeType = "AUTHORIZATION"
	NodeEvidence           NodeType = "EVIDENCE"
)

// Extended multi-agent relationship types (reusing EdgeType in package attackpath).
const (
	EdgeCanInvoke         EdgeType = "CAN_INVOKE"
	EdgeCanRead           EdgeType = "CAN_READ"
	EdgeCanWrite          EdgeType = "CAN_WRITE"
	EdgeCanDelegate       EdgeType = "CAN_DELEGATE"
	EdgeRetrievesFrom     EdgeType = "RETRIEVES_FROM"
	EdgeTrusts            EdgeType = "TRUSTS"
	EdgeExposes           EdgeType = "EXPOSES"
	EdgeFlowsTo           EdgeType = "FLOWS_TO"
	EdgeAuthorizedBy      EdgeType = "AUTHORIZED_BY"
	EdgeObservedExecution EdgeType = "OBSERVED_EXECUTION"
)

// AttackPathConfidence distinguishes theoretical graph reachability from
// static support, dynamic testing, and verified exploitability or blocking.
type AttackPathConfidence string

const (
	ConfidenceHypothetical        AttackPathConfidence = "HYPOTHETICAL"
	ConfidenceStaticallySupported AttackPathConfidence = "STATICALLY_SUPPORTED"
	ConfidenceDynamicallyTested   AttackPathConfidence = "DYNAMICALLY_TESTED"
	ConfidenceVerifiedExploitable AttackPathConfidence = "VERIFIED_EXPLOITABLE"
	ConfidenceVerifiedBlocked     AttackPathConfidence = "VERIFIED_BLOCKED"
	ConfidenceInconclusive        AttackPathConfidence = "INCONCLUSIVE"
)

// AttackScenarioKind enumerates the 10 representative controlled attack verification scenarios.
type AttackScenarioKind string

const (
	ScenarioPromptInjectionRetrieved AttackScenarioKind = "prompt_injection_retrieved_content"
	ScenarioMemoryPoisoning          AttackScenarioKind = "memory_poisoning"
	ScenarioUnauthorizedToolInvoke   AttackScenarioKind = "unauthorized_tool_invocation"
	ScenarioAgentToAgentPropagation  AttackScenarioKind = "agent_to_agent_instruction_propagation"
	ScenarioCapabilityEscalation     AttackScenarioKind = "capability_escalation"
	ScenarioMCPToolMisuse            AttackScenarioKind = "mcp_tool_misuse"
	ScenarioSensitiveDataFlow        AttackScenarioKind = "sensitive_data_flow"
	ScenarioUnsafeDelegation         AttackScenarioKind = "unsafe_delegation"
	ScenarioToolOutputLaundering     AttackScenarioKind = "tool_output_laundering"
	ScenarioPolicyBypassAttempt      AttackScenarioKind = "policy_bypass_attempt"
)

// AttackOutcome classifies the observed outcome of an isolated verification run.
type AttackOutcome string

const (
	AttackOutcomeExploitSucceeded AttackOutcome = "EXPLOIT_SUCCEEDED"
	AttackOutcomeBlocked          AttackOutcome = "ATTACK_BLOCKED"
	AttackOutcomeNoEffectObserved AttackOutcome = "NO_EFFECT_OBSERVED"
	AttackOutcomeInconclusive     AttackOutcome = "INCONCLUSIVE"
)

// AttackVerificationEvidence captures the complete, digest-bound evidence from
// an isolated dynamic verification of a candidate multi-agent attack path.
type AttackVerificationEvidence struct {
	EvidenceID               string                    `json:"evidence_id"`
	InitialEnvStateDigest    string                    `json:"initial_env_state_digest"`
	ScenarioID               string                    `json:"scenario_id"`
	ScenarioKind             AttackScenarioKind        `json:"scenario_kind"`
	InputArtifactDigest      string                    `json:"input_artifact_digest"`
	AuthorizedTestScope      string                    `json:"authorized_test_scope"`
	SyntheticCanaryToken     string                    `json:"synthetic_canary_token"`
	ControlledDestination    string                    `json:"controlled_destination"`
	ToolInvocations          []skil.ToolCall           `json:"tool_invocations,omitempty"`
	RuntimeObservations      []eval.RuntimeObservation `json:"runtime_observations,omitempty"`
	ExpectedSecurityProperty string                    `json:"expected_security_property"`
	ActualOutcome            AttackOutcome             `json:"actual_outcome"`
	EnforcementDenied        bool                      `json:"enforcement_denied"`
	LLMReasoningOnly         bool                      `json:"llm_reasoning_only"`
	EvidenceDigests          []string                  `json:"evidence_digests"`
	IsolationIdentity        string                    `json:"isolation_identity"`
	Complete                 bool                      `json:"complete"`
	EvidenceDigest           string                    `json:"evidence_digest"`
}

// ValidateSyntheticSafety ensures controlled attack verification uses only
// synthetic canary secrets and controlled loopback/sandbox destinations, never
// real credentials or external production endpoints.
func ValidateSyntheticSafety(canaryToken, destination, isolationID, authorizedScope string) error {
	if strings.TrimSpace(isolationID) == "" || strings.EqualFold(isolationID, "host") || strings.EqualFold(isolationID, "none") {
		return errors.New("attack verification requires an explicit isolated evaluation environment")
	}
	if strings.TrimSpace(authorizedScope) == "" {
		return errors.New("attack verification requires an explicit authorized_test_scope")
	}
	if !strings.HasPrefix(canaryToken, "SYNTHETIC-CANARY-") {
		return fmt.Errorf("attack verification must use a synthetic canary token prefixed with SYNTHETIC-CANARY-, got %q", canaryToken)
	}
	if receipt.ContainsSensitiveCredentialMaterial(canaryToken) {
		return errors.New("attack verification canary contains forbidden real-credential pattern")
	}
	destLower := strings.ToLower(strings.TrimSpace(destination))
	allowedControlledPrefixes := []string{
		"controlled://",
		"sandbox://",
		"loopback://",
		"https://127.0.0.1",
		"https://localhost",
		"http://127.0.0.1",
		"http://localhost",
	}
	allowed := false
	for _, prefix := range allowedControlledPrefixes {
		if strings.HasPrefix(destLower, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("attack verification destination %q is not a controlled sandbox/loopback sink", destination)
	}
	return nil
}

// Finalize computes the canonical digest of the AttackVerificationEvidence.
func (e AttackVerificationEvidence) Finalize() (AttackVerificationEvidence, error) {
	if err := ValidateSyntheticSafety(e.SyntheticCanaryToken, e.ControlledDestination, e.IsolationIdentity, e.AuthorizedTestScope); err != nil {
		return e, err
	}
	if e.InitialEnvStateDigest == "" || e.ScenarioID == "" || e.InputArtifactDigest == "" || e.ExpectedSecurityProperty == "" {
		return e, errors.New("attack verification evidence is missing required identity or state digests")
	}
	for i := range e.RuntimeObservations {
		e.RuntimeObservations[i] = eval.FinalizeRuntimeObservation(e.RuntimeObservations[i])
		e.EvidenceDigests = append(e.EvidenceDigests, e.RuntimeObservations[i].EvidenceDigest)
	}
	e.EvidenceDigests = uniqueSortedStrings(e.EvidenceDigests)
	copyEv := e
	copyEv.EvidenceDigest = ""
	raw, err := signing.CanonicalJSON(copyEv)
	if err != nil {
		return e, err
	}
	sum := sha256.Sum256(raw)
	e.EvidenceDigest = "sha256:" + hex.EncodeToString(sum[:])
	if e.EvidenceID == "" {
		e.EvidenceID = "atk-ev:" + hex.EncodeToString(sum[:8])
	}
	return e, nil
}

// MultiAgentAttackPath represents a candidate or verified multi-agent attack path.
type MultiAgentAttackPath struct {
	PathID               string                      `json:"path_id"`
	ScenarioKind         AttackScenarioKind          `json:"scenario_kind"`
	Nodes                []GraphNode                 `json:"nodes"`
	Edges                []GraphEdge                 `json:"edges"`
	StaticEvidenceIDs    []string                    `json:"static_evidence_ids,omitempty"`
	LLMProposed          bool                        `json:"llm_proposed,omitempty"`
	VerificationEvidence *AttackVerificationEvidence `json:"verification_evidence,omitempty"`
	Confidence           AttackPathConfidence        `json:"confidence"`
	ConfidenceReason     string                      `json:"confidence_reason"`
}

// EvaluatePathConfidence applies strict, deterministic evidence gates to classify
// an attack path's confidence.
//
// Invariants enforced:
//  1. A topological path without static edge evidence is HYPOTHETICAL.
//  2. LLM reasoning alone can NEVER produce VERIFIED_EXPLOITABLE or VERIFIED_BLOCKED.
//  3. Incomplete or inconclusive dynamic tests remain INCONCLUSIVE.
//  4. VERIFIED_EXPLOITABLE requires isolated execution + external observer proof
//     (ExternallyObserved=true, ObserverDigest!="", RuntimeIdentity!="") + EXPLOIT_SUCCEEDED.
//  5. VERIFIED_BLOCKED requires isolated execution + external observer proof +
//     ATTACK_BLOCKED with EnforcementDenied=true.
func EvaluatePathConfidence(path MultiAgentAttackPath) (AttackPathConfidence, string) {
	if len(path.Nodes) < 2 || len(path.Edges) == 0 {
		return ConfidenceHypothetical, "path has insufficient nodes or edges"
	}

	v := path.VerificationEvidence
	if v == nil {
		if len(path.StaticEvidenceIDs) > 0 && !path.LLMProposed {
			return ConfidenceStaticallySupported, "supported by deterministic static AST/taint/capability evidence"
		}
		if len(path.StaticEvidenceIDs) > 0 && path.LLMProposed {
			return ConfidenceStaticallySupported, "static evidence corroborated by semantic analysis (not dynamically verified)"
		}
		return ConfidenceHypothetical, "theoretical graph path without static or dynamic verification evidence"
	}

	if v.LLMReasoningOnly {
		if len(path.StaticEvidenceIDs) > 0 {
			return ConfidenceStaticallySupported, "LLM reasoning cannot promote path to verified without isolated runtime observation"
		}
		return ConfidenceHypothetical, "LLM reasoning alone is hypothetical without deterministic or runtime evidence"
	}

	if v.IsolationIdentity == "" || strings.EqualFold(v.IsolationIdentity, "host") || !v.Complete {
		return ConfidenceInconclusive, "dynamic verification was incomplete or lacked valid isolation identity"
	}

	hasVerifiedExternalObs := false
	hasExploitEffect := false
	for _, obs := range v.RuntimeObservations {
		if obs.ExternallyObserved && strings.TrimSpace(obs.ObserverDigest) != "" && strings.TrimSpace(obs.RuntimeIdentity) != "" {
			hasVerifiedExternalObs = true
			if obs.Occurred && !obs.Authorized {
				hasExploitEffect = true
			}
		}
	}

	switch v.ActualOutcome {
	case AttackOutcomeInconclusive:
		return ConfidenceInconclusive, "isolated verification returned an inconclusive outcome"
	case AttackOutcomeExploitSucceeded:
		if hasVerifiedExternalObs && hasExploitEffect {
			return ConfidenceVerifiedExploitable, "isolated execution produced host-observed unauthorized effect at controlled canary sink"
		}
		return ConfidenceInconclusive, "exploit outcome claimed without external host-verified runtime observation"
	case AttackOutcomeBlocked:
		if hasVerifiedExternalObs && v.EnforcementDenied {
			return ConfidenceVerifiedBlocked, "isolated execution verified that runtime enforcement blocked the attack step"
		}
		return ConfidenceDynamicallyTested, "attack did not succeed, but block lacked external observer enforcement proof"
	case AttackOutcomeNoEffectObserved:
		if hasVerifiedExternalObs {
			return ConfidenceDynamicallyTested, "isolated execution completed with external observer and no exploit effect occurred"
		}
		return ConfidenceInconclusive, "no external runtime observation recorded during test"
	default:
		return ConfidenceInconclusive, "unrecognized verification outcome"
	}
}

// VerifyAttackPathInIsolation executes a controlled attack scenario in an
// isolated evaluation harness, evaluates the confidence state, and links the
// resulting verification evidence into the existing EvidenceGraphSummary.
func VerifyAttackPathInIsolation(
	ctx context.Context,
	path MultiAgentAttackPath,
	ev AttackVerificationEvidence,
	graph *skil.EvidenceGraphSummary,
) (MultiAgentAttackPath, *skil.EvidenceGraphSummary, error) {
	if err := ctx.Err(); err != nil {
		return path, graph, err
	}
	finalEv, err := ev.Finalize()
	if err != nil {
		return path, graph, err
	}
	path.VerificationEvidence = &finalEv
	path.Confidence, path.ConfidenceReason = EvaluatePathConfidence(path)
	if path.PathID == "" {
		sum := sha256.Sum256([]byte(string(path.ScenarioKind) + "\x00" + finalEv.ScenarioID))
		path.PathID = "path:" + hex.EncodeToString(sum[:8])
	}
	updatedGraph := LinkAttackPathToEvidenceGraph(graph, path)
	return path, updatedGraph, nil
}

// LinkAttackPathToEvidenceGraph projects an attack path and its verification
// evidence into skil.EvidenceGraphSummary without creating a separate graph store.
func LinkAttackPathToEvidenceGraph(graph *skil.EvidenceGraphSummary, path MultiAgentAttackPath) *skil.EvidenceGraphSummary {
	if graph == nil {
		graph = &skil.EvidenceGraphSummary{}
	}
	state := skil.EvidenceInferred
	switch path.Confidence {
	case ConfidenceVerifiedExploitable, ConfidenceVerifiedBlocked:
		state = skil.EvidenceVerified
	case ConfidenceStaticallySupported, ConfidenceDynamicallyTested:
		state = skil.EvidenceObserved
	}

	seenNodes := make(map[string]int, len(graph.Nodes))
	for i, n := range graph.Nodes {
		seenNodes[n.ID] = i
	}
	upsertNode := func(n skil.EvidenceGraphNode) {
		if idx, ok := seenNodes[n.ID]; ok {
			graph.Nodes[idx] = n
		} else {
			seenNodes[n.ID] = len(graph.Nodes)
			graph.Nodes = append(graph.Nodes, n)
		}
	}

	for _, pn := range path.Nodes {
		upsertNode(skil.EvidenceGraphNode{
			ID:     "attack-entity:" + pn.ID,
			Kind:   strings.ToLower(string(pn.Type)),
			RefID:  pn.ID,
			State:  state,
			Detail: pn.Label,
		})
	}

	seenEdges := make(map[string]bool, len(graph.Edges))
	for _, e := range graph.Edges {
		seenEdges[e.From+"\x00"+e.To+"\x00"+e.Relation] = true
	}
	addEdge := func(e skil.EvidenceGraphEdge) {
		k := e.From + "\x00" + e.To + "\x00" + e.Relation
		if !seenEdges[k] {
			seenEdges[k] = true
			graph.Edges = append(graph.Edges, e)
		}
	}

	for _, pe := range path.Edges {
		addEdge(skil.EvidenceGraphEdge{
			From:      "attack-entity:" + pe.From,
			To:        "attack-entity:" + pe.To,
			Relation:  strings.ToLower(string(pe.Type)),
			State:     state,
			Rationale: fmt.Sprintf("attack path %s (%s)", path.PathID, path.Confidence),
		})
	}

	if path.VerificationEvidence != nil {
		evID := "attack-verification:" + path.VerificationEvidence.EvidenceID
		upsertNode(skil.EvidenceGraphNode{
			ID:     evID,
			Kind:   "attack-verification",
			RefID:  path.VerificationEvidence.ScenarioID,
			State:  state,
			Detail: fmt.Sprintf("%s (%s)", path.Confidence, path.VerificationEvidence.EvidenceDigest),
		})
		if len(path.Nodes) > 0 {
			lastNode := "attack-entity:" + path.Nodes[len(path.Nodes)-1].ID
			addEdge(skil.EvidenceGraphEdge{
				From:      evID,
				To:        lastNode,
				Relation:  "verifies-attack-path",
				State:     state,
				Rationale: path.ConfidenceReason,
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

// ReachabilityClassification describes how reachable an attack path is.
type ReachabilityClassification string

const (
	ReachabilityUnreachable          ReachabilityClassification = "UNREACHABLE"
	ReachabilityTopologicalOnly      ReachabilityClassification = "TOPOLOGICAL_ONLY"
	ReachabilityStaticallyReachable  ReachabilityClassification = "STATICALLY_REACHABLE"
	ReachabilityDynamicallyReachable ReachabilityClassification = "DYNAMICALLY_REACHABLE"
)

// HeuristicRiskEstimate holds clearly labeled heuristic risk indicators so they
// are never conflated with verified facts.
type HeuristicRiskEstimate struct {
	AdvisoryPriority string `json:"advisory_priority"` // P0, P1, P2, P3, P4
	SemanticSummary  string `json:"semantic_summary"`
}

// AttackPathRiskAssessment evaluates a multi-agent attack path while keeping
// verified facts strictly separate from heuristic risk estimates.
type AttackPathRiskAssessment struct {
	PathID                      string                     `json:"path_id"`
	ScenarioKind                AttackScenarioKind         `json:"scenario_kind"`
	Reachability                ReachabilityClassification `json:"reachability"`
	RequiredPrivileges          []string                   `json:"required_privileges"`
	TrustBoundariesCrossed      []string                   `json:"trust_boundaries_crossed"`
	EvidenceConfidence          AttackPathConfidence       `json:"evidence_confidence"`
	VerifiedExploitable         bool                       `json:"verified_exploitable"`
	VerifiedBlocked             bool                       `json:"verified_blocked"`
	Impact                      skil.Severity              `json:"impact"`
	ExistingEnforcementControls []string                   `json:"existing_enforcement_controls,omitempty"`
	VerifiedFacts               []string                   `json:"verified_facts"`
	HeuristicEstimate           HeuristicRiskEstimate      `json:"heuristic_estimate"`
}

// EvaluateAttackPathRisk computes a fact-separated risk assessment for a
// MultiAgentAttackPath.
func EvaluateAttackPathRisk(path MultiAgentAttackPath, activeControls []string) AttackPathRiskAssessment {
	conf, _ := EvaluatePathConfidence(path)

	reach := ReachabilityTopologicalOnly
	switch conf {
	case ConfidenceStaticallySupported:
		reach = ReachabilityStaticallyReachable
	case ConfidenceDynamicallyTested, ConfidenceVerifiedExploitable, ConfidenceVerifiedBlocked:
		reach = ReachabilityDynamicallyReachable
	}
	if len(path.Edges) == 0 {
		reach = ReachabilityUnreachable
	}

	var privs []string
	var boundaries []string
	nodeByID := make(map[string]GraphNode, len(path.Nodes))
	for _, n := range path.Nodes {
		nodeByID[n.ID] = n
		if n.Type == NodePermission || n.Type == NodeAuthorization {
			privs = append(privs, n.Label)
		}
	}
	for _, e := range path.Edges {
		fromNode := nodeByID[e.From]
		toNode := nodeByID[e.To]
		if fromNode.Type != "" && toNode.Type != "" && fromNode.Type != toNode.Type {
			boundaries = append(boundaries, fmt.Sprintf("%s->%s(%s)", fromNode.Type, toNode.Type, e.Type))
		}
	}
	privs = uniqueSortedStrings(privs)
	boundaries = uniqueSortedStrings(boundaries)
	controls := uniqueSortedStrings(activeControls)

	impact := skil.SeverityMedium
	switch path.ScenarioKind {
	case ScenarioPromptInjectionRetrieved, ScenarioMemoryPoisoning, ScenarioCapabilityEscalation,
		ScenarioSensitiveDataFlow, ScenarioUnsafeDelegation, ScenarioPolicyBypassAttempt:
		impact = skil.SeverityCritical
	case ScenarioUnauthorizedToolInvoke, ScenarioAgentToAgentPropagation, ScenarioMCPToolMisuse, ScenarioToolOutputLaundering:
		impact = skil.SeverityHigh
	}

	var verifiedFacts []string
	if conf == ConfidenceVerifiedExploitable {
		verifiedFacts = append(verifiedFacts, "exploitability_verified_in_isolated_runtime")
	}
	if conf == ConfidenceVerifiedBlocked {
		verifiedFacts = append(verifiedFacts, "runtime_enforcement_verified_to_block_attack")
	}
	if len(path.StaticEvidenceIDs) > 0 {
		verifiedFacts = append(verifiedFacts, fmt.Sprintf("backed_by_%d_deterministic_static_evidence_items", len(path.StaticEvidenceIDs)))
	}

	priority := "P2"
	summary := "Theoretical or statically supported path requiring review; not dynamically verified as exploitable."
	switch conf {
	case ConfidenceVerifiedExploitable:
		priority = "P0"
		summary = "Empirically verified exploitable multi-agent attack path in isolated runtime."
	case ConfidenceVerifiedBlocked:
		priority = "P4"
		summary = "Attack path was dynamically tested and deterministically blocked by active runtime enforcement."
	case ConfidenceStaticallySupported:
		priority = "P1"
		summary = "Statically supported multi-agent attack path; isolate and run dynamic verification."
	case ConfidenceInconclusive:
		priority = "P2"
		summary = "Dynamic verification was inconclusive; cannot assume safety."
	}

	return AttackPathRiskAssessment{
		PathID:                      path.PathID,
		ScenarioKind:                path.ScenarioKind,
		Reachability:                reach,
		RequiredPrivileges:          privs,
		TrustBoundariesCrossed:      boundaries,
		EvidenceConfidence:          conf,
		VerifiedExploitable:         conf == ConfidenceVerifiedExploitable,
		VerifiedBlocked:             conf == ConfidenceVerifiedBlocked,
		Impact:                      impact,
		ExistingEnforcementControls: controls,
		VerifiedFacts:               verifiedFacts,
		HeuristicEstimate: HeuristicRiskEstimate{
			AdvisoryPriority: priority,
			SemanticSummary:  summary,
		},
	}
}

func uniqueSortedStrings(in []string) []string {
	m := make(map[string]bool, len(in))
	for _, s := range in {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			m[trimmed] = true
		}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

