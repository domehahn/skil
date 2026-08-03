package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func multiAgentFindings(t *testing.T, path, content string) []skil.Finding {
	t.Helper()
	findings, err := NewMultiAgent().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith(path, content)})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestUnverifiedAgentIdentityIsDetected(t *testing.T) {
	content := "agent_id = request.headers.get('X-Agent-Id')\n"
	findings := multiAgentFindings(t, "handler.py", content)
	if !hasRule(findings, "SKIL-A2A-001") {
		t.Fatalf("expected an unverified agent identity claim to be detected: %#v", findings)
	}
}

func TestVerifiedAgentIdentityIsSafe(t *testing.T) {
	content := "agent_id = verify_agent_signature(payload)\n"
	findings := multiAgentFindings(t, "handler.py", content)
	if hasRule(findings, "SKIL-A2A-001") {
		t.Fatalf("a signature-verified agent identity should not fire: %#v", findings)
	}
}

func TestCrossAgentOutputIntoExecIsDetected(t *testing.T) {
	content := "response = call_peer_agent(task)\neval(agent_response)\n"
	findings := multiAgentFindings(t, "orchestrator.py", content)
	if !hasRule(findings, "SKIL-A2A-003") {
		t.Fatalf("expected unsanitized cross-agent output reaching eval to be detected: %#v", findings)
	}
}

func TestSanitizedCrossAgentOutputIsSafe(t *testing.T) {
	content := "sanitized = sanitize(agent_response)\nresult = json.loads(sanitized)\n"
	findings := multiAgentFindings(t, "orchestrator.py", content)
	if hasRule(findings, "SKIL-A2A-003") {
		t.Fatalf("sanitized cross-agent output should not fire: %#v", findings)
	}
}

func TestCrossTenantBypassIsDetected(t *testing.T) {
	content := "call_agent(target, tenant=other_tenant, verify_tenant=False)\n"
	findings := multiAgentFindings(t, "gateway.py", content)
	if !hasRule(findings, "SKIL-A2A-005") {
		t.Fatalf("expected an explicit tenant-verification bypass to be detected: %#v", findings)
	}
}

func TestOrdinaryTenantScopedCallIsSafe(t *testing.T) {
	content := "call_agent(target, tenant=current_tenant)\n"
	findings := multiAgentFindings(t, "gateway.py", content)
	if hasRule(findings, "SKIL-A2A-005") {
		t.Fatalf("an ordinary tenant-scoped call should not fire: %#v", findings)
	}
}

func TestCircularDelegationIsDetected(t *testing.T) {
	content := `agents:
  - id: coordinator
    scope: [read_repo]
    delegates_to: [worker]
  - id: worker
    scope: [read_repo]
    delegates_to: [coordinator]
`
	findings := multiAgentFindings(t, "delegation.yaml", content)
	if !hasRule(findings, "SKIL-A2A-004") {
		t.Fatalf("expected a circular delegation to be detected: %#v", findings)
	}
}

func TestAcyclicDelegationIsSafe(t *testing.T) {
	content := `agents:
  - id: coordinator
    scope: [read_repo]
    delegates_to: [worker]
  - id: worker
    scope: [read_repo]
    delegates_to: []
`
	findings := multiAgentFindings(t, "delegation.yaml", content)
	if hasRule(findings, "SKIL-A2A-004") {
		t.Fatalf("an acyclic delegation chain should not fire: %#v", findings)
	}
}

func TestDelegatedAuthorityEscalationIsDetected(t *testing.T) {
	content := `agents:
  - id: coordinator
    scope: [read_repo]
    delegates_to: [worker]
  - id: worker
    scope: [read_repo, write_repo, delete_repo]
    delegates_to: []
`
	findings := multiAgentFindings(t, "delegation.yaml", content)
	if !hasRule(findings, "SKIL-A2A-002") {
		t.Fatalf("expected a delegate with broader scope than its delegator to be detected: %#v", findings)
	}
}

func TestScopeContainedDelegationIsSafe(t *testing.T) {
	content := `agents:
  - id: coordinator
    scope: [read_repo, write_repo]
    delegates_to: [worker]
  - id: worker
    scope: [read_repo]
    delegates_to: []
`
	findings := multiAgentFindings(t, "delegation.yaml", content)
	if hasRule(findings, "SKIL-A2A-002") {
		t.Fatalf("a delegate scoped within its delegator's scope should not fire: %#v", findings)
	}
}
