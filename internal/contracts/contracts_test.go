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

func minimalCapabilities() string {
	return `capabilities:
  filesystem: {read: [], write: [], delete: []}
  network: {inbound: false, outbound: false, hosts: []}
  commands: {execute: false, allow: []}
  secrets: {read: [], expose: false}
  environment: {read: []}
  tools: {allow: [], deny: []}
  mcp: {servers: [], tools: []}
  persistence: false
  agent: {autonomous_actions: false, external_side_effects: false, confirm_destructive: false, confirm_external: false}
`
}

func TestContractAcceptsReviewedClosureWithValidDigest(t *testing.T) {
	digest := strings.Repeat("a", 64)
	_, err := Parse([]byte("version: 1\nskill: {name: x, description: x}\n" + minimalCapabilities() +
		"reviewed_closure:\n  - identifier: helper-plugin\n    sha256: " + digest + "\n"))
	if err != nil {
		t.Fatalf("expected a valid reviewed_closure entry to be accepted: %v", err)
	}
}

func TestContractRejectsReviewedClosureShortDigest(t *testing.T) {
	_, err := Parse([]byte("version: 1\nskill: {name: x, description: x}\n" + minimalCapabilities() +
		"reviewed_closure:\n  - identifier: helper-plugin\n    sha256: deadbeef\n"))
	if err == nil {
		t.Fatal("expected a non-64-character sha256 digest to be rejected")
	}
}

func TestContractRejectsReviewedClosureDuplicateIdentifier(t *testing.T) {
	digest := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	_, err := Parse([]byte("version: 1\nskill: {name: x, description: x}\n" + minimalCapabilities() +
		"reviewed_closure:\n  - identifier: helper-plugin\n    sha256: " + digest +
		"\n  - identifier: helper-plugin\n    sha256: " + other + "\n"))
	if err == nil {
		t.Fatal("expected a duplicate reviewed_closure identifier to be rejected")
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

func TestContractAcceptsPortableSecurityMetadataAndChecksConsistency(t *testing.T) {
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
		t.Fatalf("portable metadata not retained: %#v", contract)
	}
	inconsistent := append([]byte(nil), document...)
	inconsistent = []byte(strings.Replace(string(inconsistent), "runs_commands: false", "runs_commands: true", 1))
	if _, err := Parse(inconsistent); err == nil {
		t.Fatal("inconsistent security summary must be rejected")
	}
}

func TestPortableContractNormalizesFailClosed(t *testing.T) {
	document := []byte(`contract_version: 1
name: reviewer
version: 1.2.3
description: Reviews changes
owner: platform
entrypoint: SKILL.md
security:
  requires_network: false
  requires_secrets: false
  writes_files: false
  runs_commands: false
`)
	contract, err := Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	if contract.Skill.Name != "reviewer" || contract.Skill.Version != "1.2.3" ||
		contract.Security == nil || !contract.Capabilities.Agent.ConfirmExternal {
		t.Fatalf("portable contract was not normalized safely: %#v", contract)
	}
	active := []byte(strings.Replace(string(document), "requires_network: false", "requires_network: true", 1))
	if _, err := Parse(active); err == nil {
		t.Fatal("active portable posture without a concrete allowlist must fail closed")
	}
}

func TestUniversalSkillManifestIsRecognizedWithoutWeakeningPortableContracts(t *testing.T) {
	document := []byte(`name: reviewer
version: 1.2.3
description: Reviews changes
entrypoint: SKILL.md
license: MIT
owners: [platform]
compatible_with: [codex, claude-code]
`)
	contract, format, err := ParseWithFormat(document)
	if err != nil {
		t.Fatal(err)
	}
	if format != FormatUniversal || contract.Owner != "platform" ||
		len(contract.Compatibility.Agents) != 2 || !contract.Capabilities.Agent.ConfirmExternal {
		t.Fatalf("universal manifest was not normalized safely: format=%s contract=%#v", format, contract)
	}
	malformedPortable := []byte(`name: reviewer
version: 1.2.3
description: Reviews changes
owner: platform
entrypoint: SKILL.md
security:
  requires_network: false
  requires_secrets: false
  writes_files: false
  runs_commands: false
`)
	if _, _, err := ParseWithFormat(malformedPortable); err == nil {
		t.Fatal("portable contract without contract_version must remain invalid")
	}
}
