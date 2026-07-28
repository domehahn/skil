package eval

import (
	"context"
	"github.com/domehahn/skil/pkg/skil"
	"testing"
	"time"
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
