package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ConstraintEffect is the declared disposition for an authorization constraint.
type ConstraintEffect string

const (
	EffectAllow ConstraintEffect = "ALLOW"
	EffectDeny  ConstraintEffect = "DENY"
)

// ConstraintIntegrity describes whether a constraint survived a context boundary.
type ConstraintIntegrity string

const (
	ConstraintPreserved   ConstraintIntegrity = "PRESERVED"
	ConstraintWeakened    ConstraintIntegrity = "WEAKENED"
	ConstraintLost        ConstraintIntegrity = "LOST"
	ConstraintConflicting ConstraintIntegrity = "CONFLICTING"
	ConstraintUnknown     ConstraintIntegrity = "UNKNOWN"
)

type EvidenceRef struct {
	ID       string `json:"id" yaml:"id"`
	Artifact string `json:"artifact,omitempty" yaml:"artifact,omitempty"`
	Location string `json:"location,omitempty" yaml:"location,omitempty"`
}

// AuthorizationConstraint is a digest-bound statement of authority. ID and
// Digest are derived when omitted; callers cannot silently substitute a stale digest.
type AuthorizationConstraint struct {
	ID                   string           `json:"id" yaml:"id"`
	PrincipalID          string           `json:"principal_id" yaml:"principal_id"`
	Action               string           `json:"action" yaml:"action"`
	Resource             string           `json:"resource" yaml:"resource"`
	Scope                string           `json:"scope" yaml:"scope"`
	Effect               ConstraintEffect `json:"effect" yaml:"effect"`
	RequiresConfirmation bool             `json:"requires_confirmation" yaml:"requires_confirmation"`
	Provenance           EvidenceRef      `json:"provenance" yaml:"provenance"`
	Digest               string           `json:"digest" yaml:"digest"`
}

func (c AuthorizationConstraint) Finalize() (AuthorizationConstraint, error) {
	c.PrincipalID = strings.TrimSpace(c.PrincipalID)
	c.Action = strings.TrimSpace(c.Action)
	c.Resource = strings.TrimSpace(c.Resource)
	c.Scope = strings.TrimSpace(c.Scope)
	if c.PrincipalID == "" || c.Action == "" || c.Resource == "" || c.Scope == "" {
		return c, errors.New("authorization constraint requires principal, action, resource, and scope")
	}
	if c.Effect != EffectAllow && c.Effect != EffectDeny {
		return c, fmt.Errorf("unknown authorization effect %q", c.Effect)
	}
	payload := struct {
		PrincipalID          string           `json:"principal_id"`
		Action               string           `json:"action"`
		Resource             string           `json:"resource"`
		Scope                string           `json:"scope"`
		Effect               ConstraintEffect `json:"effect"`
		RequiresConfirmation bool             `json:"requires_confirmation"`
		Provenance           EvidenceRef      `json:"provenance"`
	}{c.PrincipalID, c.Action, c.Resource, c.Scope, c.Effect, c.RequiresConfirmation, c.Provenance}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	c.Digest = "sha256:" + hex.EncodeToString(sum[:])
	if c.ID == "" {
		c.ID = "constraint:" + hex.EncodeToString(sum[:8])
	}
	return c, nil
}

func constraintKey(c AuthorizationConstraint) string {
	return strings.Join([]string{c.Action, c.Resource, c.Scope}, "\x00")
}

type AuthorityDrift struct {
	ConstraintID string                   `json:"constraint_id" yaml:"constraint_id"`
	Boundary     string                   `json:"boundary" yaml:"boundary"`
	State        ConstraintIntegrity      `json:"state" yaml:"state"`
	Reason       string                   `json:"reason" yaml:"reason"`
	Declared     *AuthorizationConstraint `json:"declared,omitempty" yaml:"declared,omitempty"`
	Effective    *AuthorizationConstraint `json:"effective,omitempty" yaml:"effective,omitempty"`
}

// CompareConstraints is conservative: absent or ambiguous effective authority
// never counts as preservation. Principal IDs may differ across delegation,
// so continuity is matched on action/resource/scope.
func CompareConstraints(declared, effective []AuthorizationConstraint, boundary string) []AuthorityDrift {
	byKey := make(map[string][]AuthorizationConstraint)
	for _, c := range effective {
		byKey[constraintKey(c)] = append(byKey[constraintKey(c)], c)
	}
	var out []AuthorityDrift
	for i := range declared {
		d := declared[i]
		matches := byKey[constraintKey(d)]
		drift := AuthorityDrift{ConstraintID: d.ID, Boundary: boundary, State: ConstraintUnknown, Declared: &d}
		switch len(matches) {
		case 0:
			drift.State, drift.Reason = ConstraintLost, "declared constraint absent after boundary"
		case 1:
			e := matches[0]
			drift.Effective = &e
			switch {
			case d.Effect == EffectDeny && e.Effect == EffectAllow:
				drift.State, drift.Reason = ConstraintLost, "deny became allow"
			case d.Effect == EffectAllow && e.Effect == EffectAllow && d.RequiresConfirmation && !e.RequiresConfirmation:
				drift.State, drift.Reason = ConstraintWeakened, "confirmation requirement removed"
			case d.Effect == e.Effect && (!d.RequiresConfirmation || e.RequiresConfirmation):
				drift.State, drift.Reason = ConstraintPreserved, "constraint preserved or strengthened"
			default:
				drift.State, drift.Reason = ConstraintConflicting, "effective constraint conflicts with declaration"
			}
		default:
			drift.State, drift.Reason = ConstraintConflicting, "multiple effective constraints match the same authority"
		}
		out = append(out, drift)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ConstraintID < out[j].ConstraintID })
	return out
}

type ContextDelta struct {
	ModelIdentity       string                    `json:"model_identity,omitempty" yaml:"model_identity,omitempty"`
	ProviderIdentity    string                    `json:"provider_identity,omitempty" yaml:"provider_identity,omitempty"`
	Skills              []string                  `json:"skills,omitempty" yaml:"skills,omitempty"`
	MCPEndpoints        []string                  `json:"mcp_endpoints,omitempty" yaml:"mcp_endpoints,omitempty"`
	Hooks               []string                  `json:"hooks,omitempty" yaml:"hooks,omitempty"`
	Permissions         []string                  `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	Constraints         []AuthorizationConstraint `json:"constraints,omitempty" yaml:"constraints,omitempty"`
	PolicyDigest        string                    `json:"policy_digest,omitempty" yaml:"policy_digest,omitempty"`
	InstructionsDigest  string                    `json:"instructions_digest,omitempty" yaml:"instructions_digest,omitempty"`
	RuntimeCapabilities []string                  `json:"runtime_capabilities,omitempty" yaml:"runtime_capabilities,omitempty"`
}

type AssuranceContext struct {
	PrincipalID         string                    `json:"principal_id" yaml:"principal_id"`
	ParentPrincipalID   string                    `json:"parent_principal_id,omitempty" yaml:"parent_principal_id,omitempty"`
	WorkspaceIdentity   string                    `json:"workspace_identity" yaml:"workspace_identity"`
	SessionIdentity     string                    `json:"session_identity" yaml:"session_identity"`
	ModelIdentity       string                    `json:"model_identity" yaml:"model_identity"`
	ProviderIdentity    string                    `json:"provider_identity" yaml:"provider_identity"`
	Skills              []string                  `json:"skills,omitempty" yaml:"skills,omitempty"`
	MCPEndpoints        []string                  `json:"mcp_endpoints,omitempty" yaml:"mcp_endpoints,omitempty"`
	Hooks               []string                  `json:"hooks,omitempty" yaml:"hooks,omitempty"`
	Permissions         []string                  `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	Constraints         []AuthorizationConstraint `json:"authorization_constraints" yaml:"authorization_constraints"`
	EffectiveAuthority  []AuthorizationConstraint `json:"effective_authority" yaml:"effective_authority"`
	PolicyDigest        string                    `json:"policy_digest" yaml:"policy_digest"`
	InstructionsDigest  string                    `json:"instructions_digest" yaml:"instructions_digest"`
	RuntimeCapabilities []string                  `json:"runtime_capabilities,omitempty" yaml:"runtime_capabilities,omitempty"`
	ParentClosureDigest string                    `json:"parent_closure_digest,omitempty" yaml:"parent_closure_digest,omitempty"`
	ClosureDigest       string                    `json:"closure_digest" yaml:"closure_digest"`
	Verified            bool                      `json:"verified" yaml:"verified"`
	Limitations         []string                  `json:"limitations,omitempty" yaml:"limitations,omitempty"`
}

func FinalizeContext(c AssuranceContext) (AssuranceContext, error) {
	if c.PrincipalID == "" || c.WorkspaceIdentity == "" || c.SessionIdentity == "" {
		return c, errors.New("assurance context requires principal, workspace, and session identities")
	}
	for i := range c.Constraints {
		v, err := c.Constraints[i].Finalize()
		if err != nil {
			return c, err
		}
		c.Constraints[i] = v
	}
	for i := range c.EffectiveAuthority {
		v, err := c.EffectiveAuthority[i].Finalize()
		if err != nil {
			return c, err
		}
		c.EffectiveAuthority[i] = v
	}
	c.Skills = sortedUnique(c.Skills)
	c.MCPEndpoints = sortedUnique(c.MCPEndpoints)
	c.Hooks = sortedUnique(c.Hooks)
	c.Permissions = sortedUnique(c.Permissions)
	c.RuntimeCapabilities = sortedUnique(c.RuntimeCapabilities)
	c.Limitations = sortedUnique(c.Limitations)
	sort.Slice(c.Constraints, func(i, j int) bool { return c.Constraints[i].Digest < c.Constraints[j].Digest })
	sort.Slice(c.EffectiveAuthority, func(i, j int) bool { return c.EffectiveAuthority[i].Digest < c.EffectiveAuthority[j].Digest })
	digestable := c
	digestable.ClosureDigest = ""
	digestable.Verified = false
	b, _ := json.Marshal(digestable)
	sum := sha256.Sum256(b)
	c.ClosureDigest = "sha256:" + hex.EncodeToString(sum[:])
	return c, nil
}

// DeriveChild applies an explicit delta. Verification is never inherited: a
// child must be independently verified after its own closure is finalized.
func DeriveChild(parent AssuranceContext, principalID, sessionID, boundary string, delta ContextDelta) (AssuranceContext, []AuthorityDrift, error) {
	if principalID == "" || sessionID == "" {
		return AssuranceContext{}, nil, errors.New("child principal and session identities are required")
	}
	child := parent
	child.ParentPrincipalID = parent.PrincipalID
	child.PrincipalID = principalID
	child.SessionIdentity = sessionID
	child.ParentClosureDigest = parent.ClosureDigest
	child.ClosureDigest = ""
	child.Verified = false
	for i := range child.Constraints {
		child.Constraints[i].PrincipalID = principalID
		child.Constraints[i].Digest = ""
	}
	for i := range child.EffectiveAuthority {
		child.EffectiveAuthority[i].PrincipalID = principalID
		child.EffectiveAuthority[i].Digest = ""
	}
	apply := func(dst *[]string, src []string) {
		if src != nil {
			*dst = append([]string(nil), src...)
		}
	}
	if delta.ModelIdentity != "" {
		child.ModelIdentity = delta.ModelIdentity
	}
	if delta.ProviderIdentity != "" {
		child.ProviderIdentity = delta.ProviderIdentity
	}
	apply(&child.Skills, delta.Skills)
	apply(&child.MCPEndpoints, delta.MCPEndpoints)
	apply(&child.Hooks, delta.Hooks)
	apply(&child.Permissions, delta.Permissions)
	apply(&child.RuntimeCapabilities, delta.RuntimeCapabilities)
	if delta.PolicyDigest != "" {
		child.PolicyDigest = delta.PolicyDigest
	}
	if delta.InstructionsDigest != "" {
		child.InstructionsDigest = delta.InstructionsDigest
	}
	if delta.Constraints != nil {
		child.EffectiveAuthority = append([]AuthorizationConstraint(nil), delta.Constraints...)
		for i := range child.EffectiveAuthority {
			child.EffectiveAuthority[i].PrincipalID = principalID
			child.EffectiveAuthority[i].Digest = ""
		}
	}
	drifts := CompareConstraints(parent.EffectiveAuthority, child.EffectiveAuthority, boundary)
	for _, d := range drifts {
		if d.State != ConstraintPreserved {
			child.Limitations = append(child.Limitations, "authority "+strings.ToLower(string(d.State))+" at "+boundary+": "+d.Reason)
		}
	}
	final, err := FinalizeContext(child)
	return final, drifts, err
}

type PrincipalKind string

const (
	PrincipalHuman     PrincipalKind = "human"
	PrincipalAgent     PrincipalKind = "agent"
	PrincipalSubagent  PrincipalKind = "subagent"
	PrincipalMCP       PrincipalKind = "mcp_server"
	PrincipalTool      PrincipalKind = "tool"
	PrincipalProvider  PrincipalKind = "provider"
	PrincipalRuntime   PrincipalKind = "runtime"
	PrincipalWorkspace PrincipalKind = "workspace"
)

type AuthorityRelation string

const (
	RelationDelegatesTo   AuthorityRelation = "DELEGATES_TO"
	RelationCanInvoke     AuthorityRelation = "CAN_INVOKE"
	RelationAuthorizedFor AuthorityRelation = "AUTHORIZED_FOR"
	RelationDeniedFor     AuthorityRelation = "DENIED_FOR"
	RelationExecutes      AuthorityRelation = "EXECUTES"
	RelationControls      AuthorityRelation = "CONTROLS"
	RelationCalls         AuthorityRelation = "CALLS"
)

type Principal struct {
	ID   string        `json:"id"`
	Kind PrincipalKind `json:"kind"`
}
type AuthorityEdge struct {
	From, To   string
	Relation   AuthorityRelation
	Capability string
	Evidence   EvidenceRef
}
type AuthorityGraph struct {
	Principals                   []Principal
	Edges                        []AuthorityEdge
	MaxNodes, MaxEdges, MaxDepth int
}
type CapabilityEscalation struct {
	PrincipalID, Capability string
	Path                    []string
	Evidence                []EvidenceRef
}

// TransitiveEscalations reports only evidence-backed paths to an explicitly
// authorized capability that the root is explicitly denied.
func (g AuthorityGraph) TransitiveEscalations(root string, denied []string) ([]CapabilityEscalation, error) {
	maxNodes, maxEdges, maxDepth := g.MaxNodes, g.MaxEdges, g.MaxDepth
	if maxNodes <= 0 {
		maxNodes = 1024
	}
	if maxEdges <= 0 {
		maxEdges = 4096
	}
	if maxDepth <= 0 {
		maxDepth = 16
	}
	if len(g.Principals) > maxNodes || len(g.Edges) > maxEdges {
		return nil, errors.New("authority graph budget exhausted")
	}
	deny := map[string]bool{}
	for _, c := range denied {
		deny[c] = true
	}
	adj := map[string][]AuthorityEdge{}
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e)
	}
	type state struct {
		id       string
		path     []string
		evidence []EvidenceRef
		depth    int
	}
	queue := []state{{id: root, path: []string{root}}}
	seen := map[string]int{root: 0}
	var out []CapabilityEscalation
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth >= maxDepth {
			continue
		}
		for _, e := range adj[cur.id] {
			if e.Evidence.ID == "" {
				continue
			}
			path := append(append([]string(nil), cur.path...), e.To)
			evidence := append(append([]EvidenceRef(nil), cur.evidence...), e.Evidence)
			if e.Relation == RelationAuthorizedFor && deny[e.Capability] {
				out = append(out, CapabilityEscalation{PrincipalID: root, Capability: e.Capability, Path: path, Evidence: evidence})
			}
			if e.Relation == RelationDelegatesTo || e.Relation == RelationCanInvoke || e.Relation == RelationCalls || e.Relation == RelationControls || e.Relation == RelationExecutes {
				if d, ok := seen[e.To]; !ok || cur.depth+1 < d {
					seen[e.To] = cur.depth + 1
					queue = append(queue, state{e.To, path, evidence, cur.depth + 1})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Capability != out[j].Capability {
			return out[i].Capability < out[j].Capability
		}
		return strings.Join(out[i].Path, "\x00") < strings.Join(out[j].Path, "\x00")
	})
	return out, nil
}
