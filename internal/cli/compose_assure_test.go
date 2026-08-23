package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestComposeAssureRequiresRuntimeCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	dir := t.TempDir()
	code := New(&stdout, &stderr).Run(context.Background(), []string{"compose", "assure", dir})
	if code != ExitInput {
		t.Fatalf("expected ExitInput without --runtime-command, got %d stderr=%s", code, stderr.String())
	}
}

func TestComposeAssureRequiresTwoSkills(t *testing.T) {
	var stdout, stderr bytes.Buffer
	dir := t.TempDir()
	writeComposeAssureSkill(t, filepath.Join(dir, "solo"), "solo-skill", "write-role", "write", "shared/cache.txt")
	code := New(&stdout, &stderr).Run(context.Background(), []string{
		"compose", "assure", dir, "--runtime-command", "/synthetic/adapter",
	})
	if code != ExitInput {
		t.Fatalf("expected ExitInput with only one skill, got %d stderr=%s", code, stderr.String())
	}
}

// TestComposeAssureCorrelatesRealCrossSkillFlowAgainstRealSandbox is the
// full end-to-end proof: two real skills (a writer and a reader), each
// with its own eval.yaml, run their behavioral eval once each — via the
// real native OS sandbox, not a mock — against one shared workspace. The
// writer really writes shared/cache.txt; the reader really reads that
// same file and really contacts https://example.com. The resulting
// operation traces are correlated into a genuine observed cross-skill
// flow, matching (or, here, exceeding, since no eval.yaml-derived
// contract declares secrets.read so skil compose's own static analysis
// predicts nothing) the toxic-flow shape skil compose predicts
// statically — proving this is a runtime-only gap the static model alone
// would have missed entirely.
func TestComposeAssureCorrelatesRealCrossSkillFlowAgainstRealSandbox(t *testing.T) {
	if os.Getenv("SKIL_REQUIRE_NATIVE_ISOLATION") != "1" {
		t.Skip("native isolation integration test requires SKIL_REQUIRE_NATIVE_ISOLATION=1")
	}
	collectionDir := t.TempDir()
	writeComposeAssureSkill(t, filepath.Join(collectionDir, "writer"), "writer-skill", "write-role", "write", "shared/cache.txt")
	writeComposeAssureSkill(t, filepath.Join(collectionDir, "reader"), "reader-skill", "read-role", "read", "shared/cache.txt")

	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{
		"compose", "assure", collectionDir, "--static-only",
		"--runtime-command", os.Args[0],
		"--runtime-args", "-test.run=TestComposeAssureAdapterHelper,--,compose-assure-adapter",
		"--format", "json",
	})
	if code != ExitGateFail {
		t.Fatalf("expected a gate failure for the observed cross-skill flow: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var result struct {
		Runs []struct {
			Skill     string `json:"Skill"`
			Evaluated bool   `json:"Evaluated"`
			Error     string `json:"Error"`
		} `json:"Runs"`
		RuntimeOnlyGaps []struct {
			WriterSkill string `json:"WriterSkill"`
			ReaderSkill string `json:"ReaderSkill"`
			Resource    string `json:"Resource"`
		} `json:"RuntimeOnlyGaps"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parse compose assure JSON output: %v\n%s", err, stdout.String())
	}
	for _, run := range result.Runs {
		if !run.Evaluated {
			t.Fatalf("expected both skills to actually evaluate: %#v (stderr=%s)", run, stderr.String())
		}
	}
	if len(result.RuntimeOnlyGaps) != 1 {
		t.Fatalf("expected exactly one observed runtime-only flow, got %#v\nfull output: %s", result.RuntimeOnlyGaps, stdout.String())
	}
	gap := result.RuntimeOnlyGaps[0]
	// The observed skill identity is the artifact's directory basename
	// (artifact.Load's Name), not the skil.yaml skill.name field — a real
	// behavior confirmed by this end-to-end run, not assumed.
	if gap.WriterSkill != "writer" || gap.ReaderSkill != "reader" || gap.Resource != "shared/cache.txt" {
		t.Fatalf("unexpected observed flow: %#v", gap)
	}
}

// writeComposeAssureSkill writes a minimal, real skill+eval.yaml fixture
// whose single behavioral eval step performs exactly one gateway
// operation (workspace.write or workspace.read) named by mode/target.
func writeComposeAssureSkill(t *testing.T, dir, name, message, mode, target string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# "+name+"\n\nFixture skill for compose assure end-to-end testing.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var capabilities, tools string
	switch mode {
	case "write":
		capabilities = `  filesystem: {read: [], write: ["**"], delete: []}
  network: {inbound: false, outbound: false, hosts: []}`
		tools = `[workspace.write]`
	case "read":
		capabilities = `  filesystem: {read: ["**"], write: [], delete: []}
  network: {inbound: false, outbound: true, hosts: ["example.com"]}`
		tools = `[workspace.read, network.get]`
	default:
		t.Fatalf("unknown mode %q", mode)
	}
	skillYAML := "version: 1\n" +
		"skill:\n  name: " + name + "\n  version: 1.0.0\n  description: Fixture skill for compose assure end-to-end testing.\n" +
		"capabilities:\n" + capabilities + "\n" +
		"  commands: {execute: false, allow: []}\n  secrets: {read: [], expose: false}\n  environment: {read: []}\n" +
		"  tools: {allow: " + tools + ", deny: []}\n  mcp: {servers: [], tools: []}\n  persistence: false\n" +
		"  agent: {autonomous_actions: false, external_side_effects: true, external_targets: [], confirm_destructive: true, confirm_external: false}\n" +
		"  resources: {max_runtime_seconds: 30, max_memory_mb: 0, max_tool_calls: 8, max_network_bytes: 65536}\n"
	if err := os.WriteFile(filepath.Join(dir, "skil.yaml"), []byte(skillYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	evalYAML := "version: 1\nname: " + name + "-eval\ntype: behavioral\n" +
		"input:\n  message: " + message + "\n" +
		"tools:\n  available: " + tools + "\n" +
		"expect:\n  allowed: " + tools + "\n  output_properties: [non_empty]\n"
	if err := os.WriteFile(filepath.Join(dir, "eval.yaml"), []byte(evalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = target // target is fixed to "shared/cache.txt" inside the adapter itself
}

// TestComposeAssureAdapterHelper is a real, self-exec'd process-runtime
// adapter driving one gateway step at a time via the actual
// GatewayExchange protocol (see internal/eval.ProcessRuntime), branching
// on the eval's own input.message to decide whether to write or read the
// shared resource — see TestComposeAssureCorrelatesRealCrossSkillFlowAgainstRealSandbox.
func TestComposeAssureAdapterHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[1] != "-test.run=TestComposeAssureAdapterHelper" {
		return
	}
	found := false
	for _, argument := range os.Args {
		if argument == "compose-assure-adapter" {
			found = true
		}
	}
	if !found {
		return
	}
	var exchange skil.GatewayExchange
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&exchange); err != nil {
		os.Exit(10)
	}
	message := exchange.Request.Test.Input.Message
	encoder := json.NewEncoder(os.Stdout)
	step := len(exchange.Results)
	switch message {
	case "write-role":
		switch step {
		case 0:
			_ = encoder.Encode(skil.GatewayMessage{Type: "tool_call", ID: "step-1", Tool: "workspace.write",
				Arguments: map[string]any{"path": "shared/cache.txt", "content": "cached-secret-value"}})
		default:
			_ = encoder.Encode(skil.GatewayMessage{Type: "final", Final: &skil.EvalTrace{
				Messages: []string{}, ToolCalls: []skil.ToolCall{}, Outputs: []string{"wrote shared cache"},
				SideEffects: []string{}, Capabilities: []string{}, Errors: []string{},
			}})
		}
	case "read-role":
		switch step {
		case 0:
			_ = encoder.Encode(skil.GatewayMessage{Type: "tool_call", ID: "step-1", Tool: "workspace.read",
				Arguments: map[string]any{"path": "shared/cache.txt"}})
		case 1:
			_ = encoder.Encode(skil.GatewayMessage{Type: "tool_call", ID: "step-2", Tool: "network.get",
				Arguments: map[string]any{"url": "https://example.com"}})
		default:
			_ = encoder.Encode(skil.GatewayMessage{Type: "final", Final: &skil.EvalTrace{
				Messages: []string{}, ToolCalls: []skil.ToolCall{}, Outputs: []string{"read shared cache and reported it"},
				SideEffects: []string{}, Capabilities: []string{}, Errors: []string{},
			}})
		}
	default:
		os.Exit(11)
	}
	os.Exit(0)
}
