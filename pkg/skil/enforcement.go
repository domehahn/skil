package skil

import "time"

// TrustLevel labels how much confidence the caller has in the data driving
// an operation, forming a lattice from raw agent/tool output up to a
// cryptographically attested source. Promotion up this lattice (e.g.
// UNTRUSTED content flowing into a context that requires AUTHORIZED) must
// never happen implicitly — see Operation.TrustVerified.
type TrustLevel string

const (
	TrustUntrusted  TrustLevel = "UNTRUSTED"
	TrustObserved   TrustLevel = "OBSERVED"
	TrustVerified   TrustLevel = "VERIFIED"
	TrustAuthorized TrustLevel = "AUTHORIZED"
	TrustAttested   TrustLevel = "ATTESTED"
)

// TrustRank orders TrustLevel for lattice comparisons; higher is more
// trusted. An empty or unrecognized TrustLevel ranks below TrustUntrusted so
// it never satisfies a RequiredTrust check by accident.
func TrustRank(level TrustLevel) int {
	switch level {
	case TrustUntrusted:
		return 1
	case TrustObserved:
		return 2
	case TrustVerified:
		return 3
	case TrustAuthorized:
		return 4
	case TrustAttested:
		return 5
	default:
		return 0
	}
}

// Effect classifies what kind of change an operation makes, independent of
// which capability it uses, so policy can gate on consequence (can this be
// undone, does it reach outside this process) rather than only on
// capability name.
type Effect string

const (
	EffectPure               Effect = "PURE"
	EffectRead               Effect = "READ"
	EffectReversibleWrite    Effect = "REVERSIBLE_WRITE"
	EffectIrreversibleWrite  Effect = "IRREVERSIBLE_WRITE"
	EffectExternalSideEffect Effect = "EXTERNAL_SIDE_EFFECT"
	EffectDestructive        Effect = "DESTRUCTIVE"
)

type Operation struct {
	Capability   string   `json:"capability"`
	Target       string   `json:"target,omitempty"`
	Command      []string `json:"command,omitempty"`
	External     bool     `json:"external,omitempty"`
	Destructive  bool     `json:"destructive,omitempty"`
	Confirmed    bool     `json:"confirmed,omitempty"`
	NetworkBytes int64    `json:"network_bytes,omitempty"`
	// Digest is the sha256 of the concrete content actually being loaded or
	// executed for this operation, when the caller can measure it (a
	// fetched script, an MCP tool binary, a loaded model or plugin). When
	// the contract's ReviewedClosure pins Target to a digest, this must
	// match it or the operation is denied.
	Digest string `json:"digest,omitempty"`
	// ModelTokens is added to the Enforcer's cumulative token budget.
	ModelTokens int64 `json:"model_tokens,omitempty"`
	// RetryCount is this operation's current attempt number (0 = first
	// attempt, not a retry); checked against MaxRetries as a per-operation
	// bound, not accumulated.
	RetryCount int `json:"retry_count,omitempty"`
	// DelegationDepth is how many agent-to-agent delegation hops preceded
	// this operation; checked against MaxDelegationDepth as a bound.
	DelegationDepth int `json:"delegation_depth,omitempty"`
	// RecursionDepth is the current recursive call depth; checked against
	// MaxRecursionDepth as a bound.
	RecursionDepth int `json:"recursion_depth,omitempty"`
	// Mutation marks this operation as an external, state-changing side
	// effect (as opposed to a read) for the cumulative MaxExternalMutations
	// budget, independent of whether it is also Destructive.
	Mutation bool `json:"mutation,omitempty"`
	// SourceTrust is the trust label of the data driving this operation
	// (e.g. TrustUntrusted for raw agent/tool output flowing into a prompt
	// or a privileged call). Empty means the operation is not data-driven
	// and the trust-boundary check is skipped.
	SourceTrust TrustLevel `json:"source_trust,omitempty"`
	// RequiredTrust is the minimum trust level the operation's destination
	// context demands. Empty means no requirement. When SourceTrust ranks
	// below RequiredTrust, TrustVerified must be true or the operation is
	// denied — trust can be promoted only through an explicit, recorded
	// verification step, never implicitly.
	RequiredTrust TrustLevel `json:"required_trust,omitempty"`
	// TrustVerified records that an explicit verification step (schema
	// validation, human review, signature check, ...) justified promoting
	// SourceTrust to satisfy RequiredTrust for this specific operation.
	TrustVerified bool `json:"trust_verified,omitempty"`
	// Effect classifies the consequence of this operation. Empty means
	// unclassified and is not checked.
	Effect Effect `json:"effect,omitempty"`
	// Idempotent declares that repeating this exact operation has no
	// additional effect beyond the first successful application. Required
	// to be true whenever RetryCount > 0 and Effect is one of
	// IRREVERSIBLE_WRITE, EXTERNAL_SIDE_EFFECT, or DESTRUCTIVE — retrying a
	// non-idempotent effectful operation risks a duplicate action.
	Idempotent bool `json:"idempotent,omitempty"`
}

// DecisionRecord is a single authorization decision, in the structured,
// replayable shape ASP-14 (auditability) calls for: what was decided and on
// what evidence, never the model's private reasoning or chain of thought.
// Anything that could carry sensitive payload content (command arguments,
// tool arguments) is reduced to a digest before being recorded, so the
// record itself never becomes a new place secrets or PII leak to.
type DecisionRecord struct {
	Timestamp       time.Time `json:"timestamp"`
	Capability      string    `json:"capability"`
	Target          string    `json:"target,omitempty"`
	ArgumentsDigest string    `json:"arguments_digest,omitempty"`
	Decision        string    `json:"decision"`
	Reason          string    `json:"reason,omitempty"`
	External        bool      `json:"external,omitempty"`
	Destructive     bool      `json:"destructive,omitempty"`
	ArtifactDigest  string    `json:"artifact_digest,omitempty"`
	ContractDigest  string    `json:"contract_digest,omitempty"`
}
