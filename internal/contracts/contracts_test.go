package contracts

import (
	"strings"
	"testing"
)

func TestContractRejectsUnboundedNetwork(t *testing.T) {
	_, err := Parse([]byte(`version: 1
skill: {name: x, description: x}
capabilities:
  network: {outbound: true}
`))
	if err == nil {
		t.Fatal("expected outbound host validation error")
	}
}

func TestContractRejectsSchemaSectionsThatAreOnlyImplicitZeroValues(t *testing.T) {
	_, err := Parse([]byte(`version: 1
skill: {name: x, description: x}
capabilities:
  filesystem: {read: [], write: [], delete: []}
`))
	if err == nil {
		t.Fatal("missing capability sections must not be accepted as zero values")
	}
}

func TestContractAcceptsSkillSpecSecurityMetadataAndChecksConsistency(t *testing.T) {
	document := []byte(`version: 1
skill: {name: reviewer, version: 1.0.0, description: Reviews code}
owner: platform-security
entrypoint: SKILL.md
compatibility: {agents: [codex], platforms: [linux]}
security:
  requires_network: false
  requires_secrets: false
  writes_files: false
  runs_commands: false
capabilities:
  filesystem: {read: [], write: [], delete: []}
  network: {inbound: false, outbound: false, hosts: []}
  commands: {execute: false, allow: []}
  secrets: {read: [], expose: false}
  environment: {read: []}
  tools: {allow: [], deny: []}
  mcp: {servers: [], tools: []}
  persistence: false
  agent: {autonomous_actions: false, external_side_effects: false, confirm_destructive: true, confirm_external: true}
  resources: {max_runtime_seconds: 30}
`)
	contract, err := Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	if contract.Security == nil || contract.Owner != "platform-security" {
		t.Fatalf("SkillSpec metadata not retained: %#v", contract)
	}
	inconsistent := append([]byte(nil), document...)
	inconsistent = []byte(strings.Replace(string(inconsistent), "runs_commands: false", "runs_commands: true", 1))
	if _, err := Parse(inconsistent); err == nil {
		t.Fatal("inconsistent security summary must be rejected")
	}
}
