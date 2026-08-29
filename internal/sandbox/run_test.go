package sandbox

import (
	"strings"
	"testing"
)

func TestRunSandboxedExecutesEcho(t *testing.T) {
	res, err := RunSandboxed([]string{"echo", "hello_sandbox"}, SandboxOptions{})
	if err != nil {
		t.Fatalf("RunSandboxed failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}

	if !strings.Contains(res.Stdout, "hello_sandbox") {
		t.Fatalf("expected stdout to contain hello_sandbox, got %q", res.Stdout)
	}
}
