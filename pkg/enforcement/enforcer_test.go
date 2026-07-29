package enforcement

import (
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
