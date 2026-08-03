package enforcement

import (
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestEnforcerAppliesAllowlistsConfirmationsAndBudgets(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Network:   skil.NetworkCapability{Outbound: true, Hosts: []string{"api.example.com"}},
		Tools:     skil.ToolCapability{Allow: []string{"git.read"}},
		Agent:     skil.AgentCapability{ExternalSideEffects: true, ConfirmExternal: true},
		Resources: skil.ResourceLimits{MaxToolCalls: 1, MaxNetworkBytes: 10},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "network.outbound", Target: "evil.example"}); err == nil {
		t.Fatal("expected host rejection")
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "network.outbound", Target: "api.example.com", External: true, NetworkBytes: 5}); err == nil {
		t.Fatal("expected confirmation requirement")
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "network.outbound", Target: "api.example.com", External: true, Confirmed: true, NetworkBytes: 5}); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "network.outbound", Target: "api.example.com", External: true, Confirmed: true, NetworkBytes: 6}); err == nil {
		t.Fatal("expected network budget rejection")
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "tools.call", Target: "git.read"}); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "tools.call", Target: "git.read"}); err == nil {
		t.Fatal("expected tool-call budget rejection")
	}
}

func TestEnforcerRejectsTraversalAndUnknownCapabilities(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Filesystem: skil.FilesystemCapability{Read: []string{"docs/**"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "filesystem.read", Target: "../secret"}); err == nil {
		t.Fatal("expected traversal rejection")
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "unknown"}); err == nil {
		t.Fatal("expected unknown capability rejection")
	}
}

func TestEnforcerRequiresStructuredCommandArguments(t *testing.T) {
	enforcer := New(skil.SkillContract{Capabilities: skil.Capabilities{
		Commands: skil.CommandCapability{Execute: true, Allow: []string{"terraform plan"}},
	}})
	if err := enforcer.Authorize(skil.Operation{Capability: "commands.execute", Target: "terraform plan; rm -rf /"}); err == nil {
		t.Fatal("legacy command strings must be rejected")
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "commands.execute", Command: []string{"terraform", "plan", "-out", "plan.tfplan"}}); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "commands.execute", Command: []string{"terraform", "apply"}}); err == nil {
		t.Fatal("argv outside the allowed prefix must be rejected")
	}
}

func TestEnforcerDerivesExternalAndDestructiveRiskFromCapability(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Filesystem: skil.FilesystemCapability{
			Write: []string{"output/**"}, Delete: []string{"output/**"},
		},
		Agent: skil.AgentCapability{
			ExternalSideEffects: true, ConfirmExternal: true, ConfirmDestructive: true,
		},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "filesystem.write", Target: "output/result.txt"}); err == nil {
		t.Fatal("filesystem writes must derive external confirmation requirements")
	}
	if err := enforcer.Authorize(skil.Operation{
		Capability: "filesystem.delete", Target: "output/result.txt", Confirmed: true,
	}); err != nil {
		t.Fatalf("confirmed allowed delete failed: %v", err)
	}
}

func TestEnforcerAppliesContainmentTargetsAndAttemptOnlyCapabilities(t *testing.T) {
	enforcer := New(skil.SkillContract{Capabilities: skil.Capabilities{
		Network: skil.NetworkCapability{Outbound: true, Hosts: []string{"challenge.internal"}},
		Agent: skil.AgentCapability{
			ExternalSideEffects: true, ExternalTargets: []string{"approved-ticket"},
		},
		Tools: skil.ToolCapability{Allow: []string{"local.tool"}},
		MCP:   skil.MCPCapability{Tools: []string{"local.mcp"}},
	}})
	for _, operation := range []skil.Operation{
		{Capability: "network.external", Target: "external.example"},
		{Capability: "network.lateral", Target: "host-b.internal"},
		{Capability: "external.action", Target: "unapproved-ticket"},
		{Capability: "tool.invoke", Target: "other.tool"},
		{Capability: "mcp.invoke", Target: "other.mcp"},
		{Capability: "privilege.escalate", Target: "proxy.internal"},
		{Capability: "runtime.escape", Target: "sandbox"},
		{Capability: "goal.boundary", Target: "answer-database"},
		{Capability: "enforcement.bypass", Target: "gateway"},
	} {
		if err := enforcer.Authorize(operation); err == nil {
			t.Fatalf("operation must be denied: %#v", operation)
		}
	}
	if err := enforcer.Authorize(skil.Operation{
		Capability: "external.action", Target: "approved-ticket", Confirmed: true,
	}); err != nil {
		t.Fatalf("exact external target was denied: %v", err)
	}
}

const reviewedDigestFixture = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestEnforcerDeniesUnreviewedDependencyLoad(t *testing.T) {
	enforcer := New(skil.SkillContract{})
	if err := enforcer.Authorize(skil.Operation{
		Capability: "dependency.load", Target: "helper-plugin", Digest: reviewedDigestFixture,
	}); err == nil {
		t.Fatal("expected a dependency with no reviewed-closure entry to be denied")
	}
}

func TestEnforcerAllowsDependencyLoadMatchingReviewedDigest(t *testing.T) {
	contract := skil.SkillContract{
		Capabilities:    skil.Capabilities{Agent: skil.AgentCapability{ExternalSideEffects: true}},
		ReviewedClosure: []skil.ReviewedDependency{{Identifier: "helper-plugin", SHA256: reviewedDigestFixture}},
	}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{
		Capability: "dependency.load", Target: "helper-plugin", Digest: reviewedDigestFixture,
	}); err != nil {
		t.Fatalf("expected a matching digest to be allowed: %v", err)
	}
}

func TestEnforcerDeniesDependencyLoadOnDigestMismatch(t *testing.T) {
	contract := skil.SkillContract{
		ReviewedClosure: []skil.ReviewedDependency{{Identifier: "helper-plugin", SHA256: reviewedDigestFixture}},
	}
	enforcer := New(contract)
	tampered := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := enforcer.Authorize(skil.Operation{
		Capability: "dependency.load", Target: "helper-plugin", Digest: tampered,
	}); err == nil {
		t.Fatal("expected a TOCTOU digest mismatch to be denied")
	}
}

func TestEnforcerDeniesDependencyLoadMissingDigest(t *testing.T) {
	contract := skil.SkillContract{
		ReviewedClosure: []skil.ReviewedDependency{{Identifier: "helper-plugin", SHA256: reviewedDigestFixture}},
	}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{
		Capability: "dependency.load", Target: "helper-plugin",
	}); err == nil {
		t.Fatal("expected a missing digest on a pinned dependency to be denied")
	}
}

func TestEnforcerReviewedClosurePinsUnrelatedCapabilitiesToo(t *testing.T) {
	contract := skil.SkillContract{
		Capabilities: skil.Capabilities{
			MCP:   skil.MCPCapability{Tools: []string{"reviewer"}},
			Agent: skil.AgentCapability{ExternalSideEffects: true},
		},
		ReviewedClosure: []skil.ReviewedDependency{
			{Identifier: "reviewer", SHA256: reviewedDigestFixture},
		},
	}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "mcp.tool", Target: "reviewer"}); err == nil {
		t.Fatal("expected an mcp.tool call against a pinned identifier without a digest to be denied")
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "mcp.tool", Target: "reviewer", Digest: reviewedDigestFixture}); err != nil {
		t.Fatalf("expected a matching digest on an unrelated capability to be allowed: %v", err)
	}
}

func TestEnforcerUnpinnedTargetsAreUnaffectedByReviewedClosure(t *testing.T) {
	contract := skil.SkillContract{
		Capabilities: skil.Capabilities{Tools: skil.ToolCapability{Allow: []string{"git.read"}}},
	}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "tools.call", Target: "git.read"}); err != nil {
		t.Fatalf("a capability with no reviewed_closure entries at all must behave exactly as before: %v", err)
	}
}

func TestEnforcerTracksModelTokenBudget(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Tools:     skil.ToolCapability{Allow: []string{"llm.call"}},
		Resources: skil.ResourceLimits{MaxModelTokens: 100},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "tools.call", Target: "llm.call", ModelTokens: 60}); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "tools.call", Target: "llm.call", ModelTokens: 60}); err == nil {
		t.Fatal("expected the cumulative model token budget to be exceeded")
	}
}

func TestEnforcerTracksExternalMutationBudget(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Agent:     skil.AgentCapability{ExternalSideEffects: true, ExternalTargets: []string{"ticket"}},
		Resources: skil.ResourceLimits{MaxExternalMutations: 1},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "external.action", Target: "ticket", Mutation: true}); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "external.action", Target: "ticket", Mutation: true}); err == nil {
		t.Fatal("expected the external mutation budget to be exceeded")
	}
}

func TestEnforcerBoundsRetriesDelegationAndRecursionDepth(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Resources: skil.ResourceLimits{MaxRetries: 2, MaxDelegationDepth: 3, MaxRecursionDepth: 4},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "unknown-noop", RetryCount: 3}); err == nil ||
		!strings.Contains(err.Error(), "retry") {
		t.Fatalf("expected a retry-count-exceeded denial, got %v", err)
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "unknown-noop", DelegationDepth: 4}); err == nil ||
		!strings.Contains(err.Error(), "delegation depth") {
		t.Fatalf("expected a delegation-depth-exceeded denial, got %v", err)
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "unknown-noop", RecursionDepth: 5}); err == nil ||
		!strings.Contains(err.Error(), "recursion depth") {
		t.Fatalf("expected a recursion-depth-exceeded denial, got %v", err)
	}
}

func TestEnforcerLedgerReflectsConsumption(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Tools:     skil.ToolCapability{Allow: []string{"git.read"}},
		Network:   skil.NetworkCapability{Outbound: true, Hosts: []string{"api.example.com"}},
		Agent:     skil.AgentCapability{ExternalSideEffects: true},
		Resources: skil.ResourceLimits{MaxToolCalls: 5, MaxNetworkBytes: 1000, MaxModelTokens: 500},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "tools.call", Target: "git.read", ModelTokens: 42}); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "network.outbound", Target: "api.example.com", NetworkBytes: 10}); err != nil {
		t.Fatal(err)
	}
	ledger := enforcer.Ledger()
	if ledger.ToolCalls.Used != 1 || ledger.ToolCalls.Limit != 5 {
		t.Fatalf("unexpected tool call ledger entry: %#v", ledger.ToolCalls)
	}
	if ledger.NetworkBytes.Used != 10 || ledger.NetworkBytes.Limit != 1000 {
		t.Fatalf("unexpected network byte ledger entry: %#v", ledger.NetworkBytes)
	}
	if ledger.ModelTokens.Used != 42 || ledger.ModelTokens.Limit != 500 {
		t.Fatalf("unexpected model token ledger entry: %#v", ledger.ModelTokens)
	}
}

func TestEnforcerRecordsAllowAndDenyDecisions(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Tools: skil.ToolCapability{Allow: []string{"git.read"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "tools.call", Target: "git.read"}); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.Authorize(skil.Operation{Capability: "tools.call", Target: "other.tool"}); err == nil {
		t.Fatal("expected an unlisted tool to be denied")
	}
	decisions := enforcer.Decisions()
	if len(decisions) != 2 {
		t.Fatalf("expected two recorded decisions, got %d: %#v", len(decisions), decisions)
	}
	if decisions[0].Decision != "allow" || decisions[0].Target != "git.read" {
		t.Fatalf("unexpected first decision record: %#v", decisions[0])
	}
	if decisions[1].Decision != "deny" || decisions[1].Reason == "" {
		t.Fatalf("expected the second decision to record a deny reason: %#v", decisions[1])
	}
	if decisions[0].ContractDigest == "" || decisions[0].ContractDigest != decisions[1].ContractDigest {
		t.Fatalf("expected a stable non-empty contract digest across decisions: %#v", decisions)
	}
}

func TestEnforcerDecisionRecordDigestsArgumentsInsteadOfRawContent(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Commands: skil.CommandCapability{Execute: true, Allow: []string{"git status"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "commands.execute", Command: []string{"git", "status"}}); err != nil {
		t.Fatal(err)
	}
	decisions := enforcer.Decisions()
	if len(decisions) != 1 {
		t.Fatalf("expected one recorded decision: %#v", decisions)
	}
	if decisions[0].ArgumentsDigest == "" {
		t.Fatal("expected a non-empty arguments digest")
	}
	for _, part := range []string{"git", "status"} {
		if strings.Contains(decisions[0].ArgumentsDigest, part) {
			t.Fatalf("arguments digest must not contain raw argument content: %#v", decisions[0])
		}
	}
}

func TestEnforcerDeniesUnverifiedTrustPromotion(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Tools: skil.ToolCapability{Allow: []string{"prompt.append"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{
		Capability: "tools.call", Target: "prompt.append",
		SourceTrust: skil.TrustUntrusted, RequiredTrust: skil.TrustAuthorized,
	}); err == nil {
		t.Fatal("expected unverified UNTRUSTED-to-AUTHORIZED promotion to be denied")
	}
}

func TestEnforcerAllowsExplicitlyVerifiedTrustPromotion(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Tools: skil.ToolCapability{Allow: []string{"prompt.append"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{
		Capability: "tools.call", Target: "prompt.append",
		SourceTrust: skil.TrustUntrusted, RequiredTrust: skil.TrustAuthorized, TrustVerified: true,
	}); err != nil {
		t.Fatalf("expected an explicitly verified promotion to be allowed: %v", err)
	}
}

func TestEnforcerAllowsSufficientTrustWithoutVerification(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Tools: skil.ToolCapability{Allow: []string{"prompt.append"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{
		Capability: "tools.call", Target: "prompt.append",
		SourceTrust: skil.TrustAttested, RequiredTrust: skil.TrustAuthorized,
	}); err != nil {
		t.Fatalf("expected sufficient trust to be allowed without an explicit verification flag: %v", err)
	}
}

func TestEnforcerUnclassifiedTrustIsUnaffected(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Tools: skil.ToolCapability{Allow: []string{"prompt.append"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{Capability: "tools.call", Target: "prompt.append"}); err != nil {
		t.Fatalf("an operation with no trust labels at all must behave exactly as before: %v", err)
	}
}

func TestEnforcerDeniesRetryOfNonIdempotentDestructiveEffect(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Agent: skil.AgentCapability{ExternalSideEffects: true},
		Tools: skil.ToolCapability{Allow: []string{"delete_cluster"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{
		Capability: "tools.call", Target: "delete_cluster", Confirmed: true,
		Effect: skil.EffectDestructive, RetryCount: 1, Idempotent: false,
	}); err == nil {
		t.Fatal("expected a retried non-idempotent destructive operation to be denied")
	}
}

func TestEnforcerAllowsRetryOfIdempotentDestructiveEffect(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Agent: skil.AgentCapability{ExternalSideEffects: true},
		Tools: skil.ToolCapability{Allow: []string{"delete_cluster"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{
		Capability: "tools.call", Target: "delete_cluster", Confirmed: true,
		Effect: skil.EffectDestructive, RetryCount: 1, Idempotent: true,
	}); err != nil {
		t.Fatalf("expected a retried idempotent destructive operation to be allowed: %v", err)
	}
}

func TestEnforcerAllowsFirstAttemptOfNonIdempotentDestructiveEffect(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Agent: skil.AgentCapability{ExternalSideEffects: true},
		Tools: skil.ToolCapability{Allow: []string{"delete_cluster"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{
		Capability: "tools.call", Target: "delete_cluster", Confirmed: true,
		Effect: skil.EffectDestructive, RetryCount: 0, Idempotent: false,
	}); err != nil {
		t.Fatalf("expected a first attempt (not a retry) to be allowed regardless of idempotency: %v", err)
	}
}

func TestEnforcerDestructiveEffectRequiresConfirmation(t *testing.T) {
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Agent: skil.AgentCapability{ExternalSideEffects: true, ConfirmDestructive: true},
		Tools: skil.ToolCapability{Allow: []string{"delete_cluster"}},
	}}
	enforcer := New(contract)
	if err := enforcer.Authorize(skil.Operation{
		Capability: "tools.call", Target: "delete_cluster", Effect: skil.EffectDestructive,
	}); err == nil {
		t.Fatal("expected an Effect-derived destructive operation to require confirmation")
	}
}
