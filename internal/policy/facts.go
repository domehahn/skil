package policy

import (
	"errors"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type FactKind string

const (
	FactSensitiveRead         FactKind = "sensitive_resource_read"
	FactNetworkEgress         FactKind = "network_egress"
	FactShellExecution        FactKind = "shell_execution"
	FactDynamicExecution      FactKind = "dynamic_execution"
	FactAuthorizationWeakened FactKind = "authorization_weakened"
	FactDelegationEscalation  FactKind = "delegation_escalation"
	FactRuntimeViolation      FactKind = "runtime_violation"
	FactMutableComponent      FactKind = "mutable_component"
)

type SecurityFact struct {
	ID          string
	Kind        FactKind
	Subject     string
	State       skil.EvidenceState
	EvidenceIDs []string
}
type PromotionStage string

const (
	PromotionExperimental PromotionStage = "EXPERIMENTAL"
	PromotionShadow       PromotionStage = "SHADOW"
	PromotionBenchmarked  PromotionStage = "BENCHMARKED"
	PromotionEnforce      PromotionStage = "ENFORCE"
)

type PromotionEvidence struct {
	Recall, FalsePositiveRate                  float64
	HardNegativePass, Deterministic, Monotonic bool
	BenchmarkDigest                            string
}

type AssuranceEnforcementState struct {
	RequiredClosureIncomplete      bool
	RequiredIdentityUnresolved     bool
	AuthorizationWeakened          bool
	UnverifiedChild                bool
	TransitiveCapabilityEscalation bool
	MutableComponentDrift          bool
	MCPTopologyDrift               bool
	BehavioralAssuranceStale       bool
	RuntimeVerifiedViolation       bool
	RequiredBudgetExhausted        bool
	EvidenceVerified               bool
}

// EnforcementReasons only promotes evidence-backed state. A caller must opt
// into suspected/unverified facts through a separate policy path.
func EnforcementReasons(state AssuranceEnforcementState) []string {
	if !state.EvidenceVerified {
		return nil
	}
	var reasons []string
	checks := []struct {
		active bool
		reason string
	}{{state.RequiredClosureIncomplete, "required_closure_incomplete"}, {state.RequiredIdentityUnresolved, "required_identity_unresolved"}, {state.AuthorizationWeakened, "authorization_weakened"}, {state.UnverifiedChild, "unverified_child_agent"}, {state.TransitiveCapabilityEscalation, "transitive_capability_escalation"}, {state.MutableComponentDrift, "mutable_component_drift"}, {state.MCPTopologyDrift, "mcp_topology_drift"}, {state.BehavioralAssuranceStale, "behavioral_assurance_stale"}, {state.RuntimeVerifiedViolation, "runtime_verified_violation"}, {state.RequiredBudgetExhausted, "required_analysis_budget_exhausted"}}
	for _, check := range checks {
		if check.active {
			reasons = append(reasons, check.reason)
		}
	}
	sort.Strings(reasons)
	return reasons
}

func Promote(current PromotionStage, evidence PromotionEvidence) (PromotionStage, error) {
	switch current {
	case PromotionExperimental:
		return PromotionShadow, nil
	case PromotionShadow:
		if evidence.BenchmarkDigest == "" || evidence.Recall < 0.95 || evidence.FalsePositiveRate > 0.05 || !evidence.HardNegativePass || !evidence.Deterministic || !evidence.Monotonic {
			return current, errors.New("promotion criteria not met")
		}
		return PromotionBenchmarked, nil
	case PromotionBenchmarked:
		if evidence.BenchmarkDigest == "" || !evidence.HardNegativePass || !evidence.Deterministic || !evidence.Monotonic {
			return current, errors.New("enforcement promotion criteria not met")
		}
		return PromotionEnforce, nil
	case PromotionEnforce:
		return current, nil
	default:
		return current, errors.New("unknown promotion stage")
	}
}

func CanonicalFacts(facts []SecurityFact) []SecurityFact {
	out := append([]SecurityFact(nil), facts...)
	for i := range out {
		out[i].EvidenceIDs = append([]string(nil), out[i].EvidenceIDs...)
		sort.Strings(out[i].EvidenceIDs)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Join([]string{out[i].ID, string(out[i].Kind), out[i].Subject}, "\x00") < strings.Join([]string{out[j].ID, string(out[j].Kind), out[j].Subject}, "\x00")
	})
	return out
}
