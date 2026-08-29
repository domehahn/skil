package enforcement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

type Enforcer struct {
	mu                sync.Mutex
	contract          skil.SkillContract
	contractDigest    string
	started           time.Time
	toolCalls         int
	networkBytes      int64
	modelTokens       int64
	externalMutations int
	decisions         []skil.DecisionRecord
	startupError      error
}

func New(contract skil.SkillContract) *Enforcer {
	return NewWithAssurance(contract, "", "")

}

// NewWithAssurance binds runtime startup to the measured root and closure
// digests. Existing contracts without those optional pins behave exactly as
// before; configured pins fail closed when measurements are absent or differ.
func NewWithAssurance(contract skil.SkillContract, rootDigest, closureDigest string) *Enforcer {
	e := &Enforcer{contract: contract, contractDigest: contractDigest(contract), started: time.Now()}
	if contract.ReviewedRootDigest != "" && !strings.EqualFold(contract.ReviewedRootDigest, rootDigest) {
		e.startupError = fmt.Errorf("runtime root digest %q does not match reviewed root digest %q", rootDigest, contract.ReviewedRootDigest)
	}
	if e.startupError == nil && contract.ReviewedClosureDigest != "" && !strings.EqualFold(contract.ReviewedClosureDigest, closureDigest) {
		e.startupError = fmt.Errorf("runtime closure digest %q does not match reviewed closure digest %q", closureDigest, contract.ReviewedClosureDigest)
	}
	return e
}

func contractDigest(contract skil.SkillContract) string {
	canonical, err := json.Marshal(contract)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func argumentsDigest(operation skil.Operation) string {
	if len(operation.Command) == 0 && operation.Target == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join(append([]string{operation.Target}, operation.Command...), "\x00")))
	return hex.EncodeToString(sum[:])
}

// Decisions returns every authorization decision recorded so far, in the
// order they were made. The slice returned is a copy: callers may retain
// and export it (e.g. into an audit log) without racing further Authorize
// calls.
func (e *Enforcer) Decisions() []skil.DecisionRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]skil.DecisionRecord, len(e.decisions))
	copy(out, e.decisions)
	return out
}

func (e *Enforcer) record(operation skil.Operation, err error) error {
	decision := "allow"
	reason := ""
	if err != nil {
		decision = "deny"
		reason = err.Error()
	}
	e.decisions = append(e.decisions, skil.DecisionRecord{
		Timestamp: time.Now(), Capability: operation.Capability, Target: operation.Target,
		ArgumentsDigest: argumentsDigest(operation), Decision: decision, Reason: reason,
		External: operation.External, Destructive: operation.Destructive,
		ArtifactDigest: operation.Digest, ContractDigest: e.contractDigest,
	})
	return err
}

// BudgetUsage reports the current consumption of a single budget dimension
// against its contract limit. Limit is 0 when the contract declared no
// limit for that dimension (unbounded).
type BudgetUsage struct {
	Used  int64 `json:"used"`
	Limit int64 `json:"limit"`
}

// BudgetLedger is a point-in-time snapshot of every cumulative budget the
// Enforcer tracks, letting a caller observe how close a running skill is to
// each of its resource limits instead of only finding out when a limit is
// finally exceeded and an operation is denied.
type BudgetLedger struct {
	RuntimeSeconds    BudgetUsage `json:"runtime_seconds"`
	ToolCalls         BudgetUsage `json:"tool_calls"`
	NetworkBytes      BudgetUsage `json:"network_bytes"`
	ModelTokens       BudgetUsage `json:"model_tokens"`
	ExternalMutations BudgetUsage `json:"external_mutations"`
}

// Ledger returns a snapshot of current budget consumption. Runtime bounds
// (retries, delegation depth, recursion depth) are per-operation checks
// rather than running totals and so have no meaningful ledger entry.
func (e *Enforcer) Ledger() BudgetLedger {
	e.mu.Lock()
	defer e.mu.Unlock()
	limits := e.contract.Capabilities.Resources
	return BudgetLedger{
		RuntimeSeconds:    BudgetUsage{Used: int64(time.Since(e.started).Seconds()), Limit: limits.MaxRuntimeSeconds},
		ToolCalls:         BudgetUsage{Used: int64(e.toolCalls), Limit: int64(limits.MaxToolCalls)},
		NetworkBytes:      BudgetUsage{Used: e.networkBytes, Limit: limits.MaxNetworkBytes},
		ModelTokens:       BudgetUsage{Used: e.modelTokens, Limit: limits.MaxModelTokens},
		ExternalMutations: BudgetUsage{Used: int64(e.externalMutations), Limit: int64(limits.MaxExternalMutations)},
	}
}

func (e *Enforcer) Authorize(operation skil.Operation) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.startupError != nil {
		return e.record(operation, e.startupError)
	}
	if operation.Capability == "" {
		return e.record(operation, errors.New("operation capability is required"))
	}
	operation = classifyOperationRisk(operation)
	if limit := e.contract.Capabilities.Resources.MaxRuntimeSeconds; limit > 0 &&
		time.Since(e.started) > time.Duration(limit)*time.Second {
		return e.record(operation, errors.New("maximum runtime exceeded"))
	}
	if operation.Destructive && e.contract.Capabilities.Agent.ConfirmDestructive && !operation.Confirmed {
		return e.record(operation, errors.New("destructive operation requires confirmation"))
	}
	if operation.External && e.contract.Capabilities.Agent.ConfirmExternal && !operation.Confirmed {
		return e.record(operation, errors.New("external operation requires confirmation"))
	}
	if operation.External && !e.contract.Capabilities.Agent.ExternalSideEffects {
		return e.record(operation, errors.New("external side effects are not allowed"))
	}
	if limit := e.contract.Capabilities.Resources.MaxRetries; limit > 0 && operation.RetryCount > limit {
		return e.record(operation, errors.New("maximum retry count exceeded"))
	}
	if limit := e.contract.Capabilities.Resources.MaxDelegationDepth; limit > 0 && operation.DelegationDepth > limit {
		return e.record(operation, errors.New("maximum delegation depth exceeded"))
	}
	if limit := e.contract.Capabilities.Resources.MaxRecursionDepth; limit > 0 && operation.RecursionDepth > limit {
		return e.record(operation, errors.New("maximum recursion depth exceeded"))
	}
	if err := verifyTrustBoundary(operation); err != nil {
		return e.record(operation, err)
	}
	if err := verifyIdempotencyOnRetry(operation); err != nil {
		return e.record(operation, err)
	}
	if err := e.authorizeCapability(operation); err != nil {
		return e.record(operation, err)
	}
	if err := e.verifyReviewedClosure(operation); err != nil {
		return e.record(operation, err)
	}
	if operation.Capability == "tools.call" || operation.Capability == "tool.invoke" ||
		operation.Capability == "mcp.tool" || operation.Capability == "mcp.invoke" {
		if limit := e.contract.Capabilities.Resources.MaxToolCalls; limit > 0 && e.toolCalls+1 > limit {
			return e.record(operation, errors.New("maximum tool call count exceeded"))
		}
		e.toolCalls++
	}
	if operation.Capability == "network.outbound" || operation.Capability == "network.external" ||
		operation.Capability == "network.lateral" {
		if operation.NetworkBytes < 0 {
			return e.record(operation, errors.New("network byte count cannot be negative"))
		}
		if limit := e.contract.Capabilities.Resources.MaxNetworkBytes; limit > 0 &&
			e.networkBytes+operation.NetworkBytes > limit {
			return e.record(operation, errors.New("maximum network byte budget exceeded"))
		}
		e.networkBytes += operation.NetworkBytes
	}
	if operation.ModelTokens < 0 {
		return e.record(operation, errors.New("model token count cannot be negative"))
	}
	if operation.ModelTokens > 0 {
		if limit := e.contract.Capabilities.Resources.MaxModelTokens; limit > 0 &&
			e.modelTokens+operation.ModelTokens > limit {
			return e.record(operation, errors.New("maximum model token budget exceeded"))
		}
		e.modelTokens += operation.ModelTokens
	}
	if operation.Mutation {
		if limit := e.contract.Capabilities.Resources.MaxExternalMutations; limit > 0 &&
			e.externalMutations+1 > limit {
			return e.record(operation, errors.New("maximum external mutation count exceeded"))
		}
		e.externalMutations++
	}
	return e.record(operation, nil)
}

func classifyOperationRisk(operation skil.Operation) skil.Operation {
	switch operation.Capability {
	case "filesystem.write", "filesystem.delete", "network.outbound", "network.external",
		"network.lateral", "network.inbound", "secrets.expose", "mcp.tool", "mcp.invoke",
		"external.action", "persistence", "dependency.load":
		operation.External = true
	}
	if operation.Capability == "filesystem.delete" {
		operation.Destructive = true
	}
	switch operation.Effect {
	case skil.EffectDestructive:
		operation.Destructive = true
		operation.External = true
	case skil.EffectIrreversibleWrite, skil.EffectExternalSideEffect:
		operation.External = true
	}
	return operation
}

// verifyTrustBoundary enforces that data ranked below the trust level an
// operation's destination context requires can only reach that context
// through an explicit, recorded verification step — never implicitly.
// Unclassified operations (SourceTrust or RequiredTrust left empty) are not
// checked, so callers that never populate trust labels see no behavior
// change.
func verifyTrustBoundary(operation skil.Operation) error {
	if operation.SourceTrust == "" || operation.RequiredTrust == "" {
		return nil
	}
	if skil.TrustRank(operation.SourceTrust) >= skil.TrustRank(operation.RequiredTrust) {
		return nil
	}
	if operation.TrustVerified {
		return nil
	}
	return fmt.Errorf("trust boundary violation: %s-trust data reaches a %s-required context without verification",
		operation.SourceTrust, operation.RequiredTrust)
}

// verifyIdempotencyOnRetry denies retrying an operation whose effect cannot
// be safely repeated: retrying a non-idempotent irreversible write, external
// side effect, or destructive operation risks a duplicate action (e.g. a
// second charge, a second message send) rather than merely redoing work.
func verifyIdempotencyOnRetry(operation skil.Operation) error {
	if operation.RetryCount == 0 || operation.Idempotent {
		return nil
	}
	switch operation.Effect {
	case skil.EffectIrreversibleWrite, skil.EffectExternalSideEffect, skil.EffectDestructive:
		return fmt.Errorf("retrying a non-idempotent %s operation risks a duplicate action; make it idempotent or deduplicate before retrying", operation.Effect)
	}
	return nil
}

// verifyReviewedClosure enforces the TOCTOU guarantee that whatever a
// pinned identifier resolves to at execution time is byte-identical to what
// was scanned and approved. It runs for every capability, not just
// dependency.load: any operation whose Target matches an identifier in the
// contract's ReviewedClosure (an MCP tool, a fetched script, a loaded
// model...) must report a digest, and that digest must match. Operations
// whose Target has no reviewed-closure entry are unaffected, so existing
// contracts that never pin anything keep their current behavior exactly.
func (e *Enforcer) verifyReviewedClosure(operation skil.Operation) error {
	if operation.Target == "" {
		return nil
	}
	expected, pinned := reviewedDigest(e.contract.ReviewedClosure, operation.Target)
	if !pinned {
		return nil
	}
	if operation.Digest == "" {
		return fmt.Errorf("%q is pinned to a reviewed digest but no digest was reported for this execution", operation.Target)
	}
	if !strings.EqualFold(operation.Digest, expected) {
		return fmt.Errorf("%q digest %s does not match its reviewed closure digest %s (TOCTOU violation)", operation.Target, operation.Digest, expected)
	}
	return nil
}

func reviewedDigest(closure []skil.ReviewedDependency, identifier string) (string, bool) {
	for _, dependency := range closure {
		if dependency.Identifier == identifier {
			return dependency.SHA256, true
		}
	}
	return "", false
}

func (e *Enforcer) authorizeCapability(operation skil.Operation) error {
	c := e.contract.Capabilities
	deny := func() error {
		return fmt.Errorf("%s target %q is not allowed by the skill contract", operation.Capability, operation.Target)
	}
	switch operation.Capability {
	case "filesystem.read":
		if !matchPath(operation.Target, c.Filesystem.Read) {
			return deny()
		}
	case "filesystem.write":
		if !matchPath(operation.Target, c.Filesystem.Write) {
			return deny()
		}
	case "filesystem.delete":
		if !matchPath(operation.Target, c.Filesystem.Delete) {
			return deny()
		}
	case "network.outbound", "network.external", "network.lateral":
		if !c.Network.Outbound || !matchHost(operation.Target, c.Network.Hosts) {
			return deny()
		}
	case "network.inbound":
		if !c.Network.Inbound {
			return deny()
		}
	case "commands.execute":
		if operation.Target != "" || !c.Commands.Execute || !matchCommand(operation.Command, c.Commands.Allow) {
			return deny()
		}
	case "secrets.read":
		if !contains(c.Secrets.Read, operation.Target) {
			return deny()
		}
	case "secrets.expose":
		if !c.Secrets.Expose {
			return deny()
		}
	case "environment.read":
		if !contains(c.Environment.Read, operation.Target) {
			return deny()
		}
	case "tools.call", "tool.invoke":
		if contains(c.Tools.Deny, operation.Target) || !contains(c.Tools.Allow, operation.Target) {
			return deny()
		}
	case "mcp.server":
		if !contains(c.MCP.Servers, operation.Target) {
			return deny()
		}
	case "mcp.tool", "mcp.invoke":
		if !contains(c.MCP.Tools, operation.Target) {
			return deny()
		}
	case "external.action":
		if !c.Agent.ExternalSideEffects || !contains(c.Agent.ExternalTargets, operation.Target) {
			return deny()
		}
	case "privilege.escalate":
		return errors.New("privilege escalation is an attempt-only capability and cannot be granted")
	case "runtime.escape":
		return errors.New("runtime escape is an attempt-only capability and cannot be granted")
	case "enforcement.bypass":
		return errors.New("enforcement bypass is an attempt-only capability and cannot be granted")
	case "goal.boundary":
		return errors.New("goal boundary violation is an attempt-only capability and cannot be granted")
	case "persistence":
		if !c.Persistence {
			return deny()
		}
	case "dependency.load":
		// Unlike every other capability, dependency.load has no allowlist
		// of its own: the reviewed closure *is* its allowlist. A runtime
		// dependency fetched or loaded after the scan (a script, a plugin,
		// a model) may only load if it was scanned and pinned in advance;
		// there is no such thing as an unreviewed one that is still
		// permitted. The digest match itself is verified separately by
		// verifyReviewedClosure once this passes.
		if _, pinned := reviewedDigest(e.contract.ReviewedClosure, operation.Target); !pinned {
			return fmt.Errorf("dependency %q is not part of the reviewed execution closure", operation.Target)
		}
	case "agent.autonomous":
		if !c.Agent.AutonomousActions {
			return deny()
		}
	default:
		return fmt.Errorf("unknown capability %q", operation.Capability)
	}
	return nil
}

func matchPath(value string, patterns []string) bool {
	if value == "" || filepath.IsAbs(value) || strings.HasPrefix(filepath.ToSlash(value), "../") {
		return false
	}
	value = filepath.ToSlash(filepath.Clean(value))
	for _, pattern := range patterns {
		pattern = filepath.ToSlash(pattern)
		if ok, _ := filepath.Match(pattern, value); ok {
			return true
		}
		prefix := strings.TrimSuffix(pattern, "/**")
		if prefix != pattern && (value == prefix || strings.HasPrefix(value, prefix+"/")) {
			return true
		}
	}
	return false
}

func matchHost(value string, allowed []string) bool {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	for _, item := range allowed {
		item = strings.ToLower(strings.TrimSuffix(item, "."))
		if value == item || (strings.HasPrefix(item, "*.") && strings.HasSuffix(value, item[1:]) && value != item[2:]) {
			return true
		}
	}
	return false
}

func matchCommand(argv []string, allowed []string) bool {
	if len(argv) == 0 || argv[0] == "" {
		return false
	}
	for _, arg := range argv {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return false
		}
	}
	for _, item := range allowed {
		allowedFields := strings.Fields(item)
		if len(allowedFields) > 0 && len(argv) >= len(allowedFields) && slices.Equal(argv[:len(allowedFields)], allowedFields) {
			return true
		}
	}
	return false
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
