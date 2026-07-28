package eval

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

func TestMockRuntimeBehavior(t *testing.T) {
	spec := skil.EvalSpec{Name: "read", Type: "behavioral", Tools: skil.EvalTools{Available: []string{"git.read", "git.write"}},
		Expect: skil.EvalExpect{Required: []string{"git.read"}, Forbidden: []string{"git.write"}, Assertions: []string{"no_external_side_effects"}}}
	result := Run(context.Background(), MockRuntime{}, spec, skil.Artifact{}, 3)
	if result.Status != skil.StatusPass || result.Metrics.TaskSuccessRate != 1 {
		t.Fatalf("%#v", result)
	}
}

func TestProcessRuntimeFailsClosedForShellAndUnenforcedMemory(t *testing.T) {
	request := skil.EvalRequest{}
	if _, err := (ProcessRuntime{Executable: "/bin/sh", Timeout: time.Second}).Execute(context.Background(), request); err == nil {
		t.Fatal("shell adapters must be rejected")
	}
	if _, err := (ProcessRuntime{Executable: "/usr/bin/false", Timeout: time.Second, MaxMemoryMB: 16}).Execute(context.Background(), request); err == nil {
		t.Fatal("unenforceable memory limits must fail closed")
	}
}

type fixedIsolation struct {
	output string
}

func (fixedIsolation) ID() string { return "test-isolation" }
func (f fixedIsolation) Run(_ context.Context, _ IsolationRequest, stdout, _ io.Writer) error {
	_, err := io.WriteString(stdout, f.output)
	return err
}

func TestProcessRuntimeRequiresIsolationAndRejectsAdapterOwnedAuditFields(t *testing.T) {
	request := skil.EvalRequest{}
	if _, err := (ProcessRuntime{Executable: "/usr/bin/false", Timeout: time.Second}).Execute(context.Background(), request); err == nil {
		t.Fatal("an unsandboxed process runtime must fail closed")
	}
	message := `{"type":"final","final":{"messages":[],"tool_calls":[],"operations":[{"capability":"commands.execute","command":["git","status"]}],"outputs":[],"side_effects":[],"capabilities":[],"errors":[]}}`
	runtime := ProcessRuntime{Executable: "/usr/bin/false", Timeout: time.Second,
		Isolation: fixedIsolation{output: message}}
	if _, err := runtime.Execute(context.Background(), request); err == nil {
		t.Fatal("adapter-owned operation claims must be rejected")
	}
}

type sequenceIsolation struct {
	outputs []string
	inputs  [][]byte
}

func (s *sequenceIsolation) ID() string { return "sequence-isolation" }
func (s *sequenceIsolation) Run(_ context.Context, request IsolationRequest, stdout, _ io.Writer) error {
	s.inputs = append(s.inputs, append([]byte(nil), request.Stdin...))
	if len(s.outputs) == 0 {
		return fmt.Errorf("unexpected gateway step")
	}
	output := s.outputs[0]
	s.outputs = s.outputs[1:]
	_, err := io.WriteString(stdout, output)
	return err
}

func TestProcessRuntimeMediatesToolsAndBuildsTrustedTrace(t *testing.T) {
	isolation := &sequenceIsolation{outputs: []string{
		`{"type":"tool_call","id":"call-1","tool":"artifact.read","arguments":{"path":"README.md"}}`,
		`{"type":"final","final":{"messages":[],"tool_calls":[],"outputs":["done"],"side_effects":[],"capabilities":[],"errors":[]}}`,
	}}
	artifact := skil.Artifact{Files: []skil.File{{Path: "README.md", Data: []byte("safe")}}}
	tool := NewArtifactReadTool(artifact)
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Filesystem: skil.FilesystemCapability{Read: []string{"README.md"}},
		Tools:      skil.ToolCapability{Allow: []string{"artifact.read"}},
		Resources:  skil.ResourceLimits{MaxToolCalls: 2},
	}}
	request := skil.EvalRequest{Test: skil.EvalSpec{Tools: skil.EvalTools{Available: []string{"artifact.read"}}}}
	runtime := ProcessRuntime{Executable: "/usr/bin/false", Timeout: time.Second, Contract: contract,
		Isolation: isolation, Tools: map[string]skil.GatewayTool{"artifact.read": tool}}
	trace, err := runtime.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(trace.ToolCalls) != 1 || len(trace.Operations) != 2 {
		t.Fatalf("host mediation was not recorded: trace=%#v", trace)
	}
	if len(isolation.inputs) != 2 || !bytes.Contains(isolation.inputs[1], []byte(`"id":"call-1"`)) {
		t.Fatalf("tool result was not returned to adapter: %q", isolation.inputs)
	}
	if !bytes.Contains(isolation.inputs[0], []byte(`"request":{"test":`)) ||
		bytes.Contains(isolation.inputs[0], []byte(`"Test":`)) {
		t.Fatalf("gateway request does not use the stable lowercase wire contract: %s", isolation.inputs[0])
	}
}

func TestProcessRuntimeDeniesUnavailableOrUnregisteredTools(t *testing.T) {
	request := skil.EvalRequest{Test: skil.EvalSpec{Tools: skil.EvalTools{Available: []string{"git.read"}}}}
	contract := skil.SkillContract{Capabilities: skil.Capabilities{Tools: skil.ToolCapability{Allow: []string{"git.read"}}}}
	for name, runtime := range map[string]ProcessRuntime{
		"unavailable": {
			Executable: "/usr/bin/false", Timeout: time.Second, Contract: contract,
			Isolation: fixedIsolation{output: `{"type":"tool_call","id":"1","tool":"git.write","arguments":{}}`},
		},
		"unregistered": {
			Executable: "/usr/bin/false", Timeout: time.Second, Contract: contract,
			Isolation: fixedIsolation{output: `{"type":"tool_call","id":"1","tool":"git.read","arguments":{}}`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runtime.Execute(context.Background(), request); err == nil {
				t.Fatal("untrusted tool request must fail closed")
			}
		})
	}
}

func TestProcessRuntimeDeniesToolWhoseDerivedCapabilityIsNotAllowed(t *testing.T) {
	artifact := skil.Artifact{Files: []skil.File{{Path: "secret.txt", Data: []byte("secret")}}}
	request := skil.EvalRequest{Test: skil.EvalSpec{Tools: skil.EvalTools{Available: []string{"artifact.read"}}}}
	contract := skil.SkillContract{Capabilities: skil.Capabilities{
		Tools: skil.ToolCapability{Allow: []string{"artifact.read"}},
	}}
	runtime := ProcessRuntime{
		Executable: "/usr/bin/false", Timeout: time.Second, Contract: contract,
		Isolation: fixedIsolation{output: `{"type":"tool_call","id":"1","tool":"artifact.read","arguments":{"path":"secret.txt"}}`},
		Tools:     map[string]skil.GatewayTool{"artifact.read": NewArtifactReadTool(artifact)},
	}
	if _, err := runtime.Execute(context.Background(), request); err == nil {
		t.Fatal("tool call must also require its derived filesystem capability")
	}
}

func TestNativeIsolationExecutesAdapterWhenAvailable(t *testing.T) {
	isolation, err := NewNativeIsolation()
	if err != nil {
		if os.Getenv("SKIL_REQUIRE_NATIVE_ISOLATION") == "1" {
			t.Fatalf("required native isolation unavailable: %v", err)
		}
		t.Skipf("native isolation unavailable: %v", err)
	}
	runtime := ProcessRuntime{
		Executable: os.Args[0], Args: []string{"-test.run=TestIsolatedAdapterHelper"},
		Timeout: 5 * time.Second, Isolation: isolation,
	}
	trace, err := runtime.Execute(context.Background(), skil.EvalRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(trace.Outputs) != 1 || trace.Outputs[0] != "isolated" {
		t.Fatalf("unexpected isolated trace: %#v", trace)
	}
	hostTarget := filepath.Join(t.TempDir(), "sandbox-escape")
	runtime.Args = []string{"-test.run=TestIsolatedAdapterHelper", "--", "deny-host-write", hostTarget}
	if _, err := runtime.Execute(context.Background(), skil.EvalRequest{}); err != nil {
		t.Fatalf("native sandbox did not prove host-write denial: %v", err)
	}
	if _, err := os.Stat(hostTarget); !os.IsNotExist(err) {
		t.Fatalf("isolated adapter wrote to host path %s", hostTarget)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	runtime.Args = []string{"-test.run=TestIsolatedAdapterHelper", "--", "deny-network", listener.Addr().String()}
	if _, err := runtime.Execute(context.Background(), skil.EvalRequest{}); err != nil {
		t.Fatalf("native sandbox did not prove network denial: %v", err)
	}
	if isolation.os == "linux" || isolation.os == "windows" {
		runtime.Args = []string{"-test.run=TestIsolatedAdapterHelper"}
		runtime.MaxMemoryMB = 2048
		if _, err := runtime.Execute(context.Background(), skil.EvalRequest{}); err != nil {
			t.Fatalf("native hard memory limit failed: %v", err)
		}
		runtime.MaxMemoryMB = 64
		runtime.Args = []string{"-test.run=TestIsolatedAdapterHelper", "--", "allocate"}
		if _, err := runtime.Execute(context.Background(), skil.EvalRequest{}); err == nil {
			t.Fatal("native hard memory limit did not stop an oversized allocation")
		}
	}
}

type limitedIsolation struct {
	fixedIsolation
	limits IsolationLimits
}

func (l *limitedIsolation) RunWithLimits(_ context.Context, _ IsolationRequest, limits IsolationLimits, stdout, _ io.Writer) error {
	l.limits = limits
	_, err := io.WriteString(stdout, l.output)
	return err
}

func TestProcessRuntimeDelegatesHardMemoryLimit(t *testing.T) {
	trace := `{"type":"final","final":{"messages":[],"tool_calls":[],"outputs":[],"side_effects":[],"capabilities":[],"errors":[]}}`
	isolation := &limitedIsolation{fixedIsolation: fixedIsolation{output: trace}}
	runtime := ProcessRuntime{Executable: "/usr/bin/false", Timeout: time.Second, MaxMemoryMB: 32, Isolation: isolation}
	if _, err := runtime.Execute(context.Background(), skil.EvalRequest{}); err != nil {
		t.Fatal(err)
	}
	if isolation.limits.MemoryBytes != 32*1024*1024 {
		t.Fatalf("memory limit not delegated: %#v", isolation.limits)
	}
}

func TestIsolatedAdapterHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[1] != "-test.run=TestIsolatedAdapterHelper" {
		return
	}
	for _, argument := range os.Args {
		if argument == "allocate" {
			memorySink = make([]byte, 256<<20)
			for index := 0; index < len(memorySink); index += 4096 {
				memorySink[index] = 1
			}
		}
	}
	if value := helperArgument("deny-host-write"); value != "" {
		if err := os.WriteFile(value, []byte("escaped"), 0o600); err == nil {
			os.Exit(9)
		}
	}
	if value := helperArgument("deny-network"); value != "" {
		connection, err := net.DialTimeout("tcp", value, 500*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			os.Exit(9)
		}
	}
	fmt.Print(`{"type":"final","final":{"messages":[],"tool_calls":[],"outputs":["isolated"],"side_effects":[],"capabilities":[],"errors":[]}}`)
	os.Exit(0)
}

var memorySink []byte

func helperArgument(name string) string {
	for index := 0; index+1 < len(os.Args); index++ {
		if os.Args[index] == name {
			return os.Args[index+1]
		}
	}
	return ""
}

type traceRuntime struct{ trace skil.EvalTrace }

func (traceRuntime) ID() string { return "trace" }
func (r traceRuntime) Execute(context.Context, skil.EvalRequest) (skil.EvalTrace, error) {
	return r.trace, nil
}

func TestEvalEnforcesAllowedArgumentsOutputAndCapabilities(t *testing.T) {
	spec := skil.EvalSpec{Name: "strict", Type: "adversarial", Tools: skil.EvalTools{Available: []string{"http.post"}},
		Expect: skil.EvalExpect{
			Allowed: []string{"git.read"}, ForbiddenCapabilities: []string{"network.outbound"},
			Arguments:        map[string]string{"http.post": `{"url":"https://allowed.example"}`},
			OutputProperties: []string{"json", "no_secrets"}, Assertions: []string{"no_errors"},
		}}
	trace := skil.EvalTrace{
		ToolCalls: []skil.ToolCall{{Name: "http.post", Allowed: true, Arguments: map[string]any{"url": "https://evil.example"}}},
		Outputs:   []string{"api_key=leaked"}, Capabilities: []string{"network.outbound"}, Errors: []string{"boom"},
	}
	result := Run(context.Background(), traceRuntime{trace: trace}, spec, skil.Artifact{}, 1)
	if result.Status != skil.StatusFail || len(result.Runs[0].Violations) < 5 {
		t.Fatalf("expected all behavioral constraints to fail: %#v", result)
	}
}

func TestEvalRejectsUnknownAssertions(t *testing.T) {
	spec := skil.EvalSpec{Name: "unknown", Tools: skil.EvalTools{}, Expect: skil.EvalExpect{Assertions: []string{"magic"}}}
	result := Run(context.Background(), MockRuntime{}, spec, skil.Artifact{}, 1)
	if result.Status != skil.StatusFail {
		t.Fatal("unknown assertions must fail closed")
	}
}
