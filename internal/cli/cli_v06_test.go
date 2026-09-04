package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLI_EvalRunCommand(t *testing.T) {
	fixtureSkill := "../../tests/fixtures/registry/kubernetes-deployer"
	var stdout, stderr bytes.Buffer
	code := RunEval([]string{"run", fixtureSkill, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected RunEval to exit 0, got %d. Stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"skill_name": "kubernetes-deployer"`) {
		t.Errorf("expected json output with skill_name kubernetes-deployer, got:\n%s", stdout.String())
	}
}

func TestCLI_ProbeCommand(t *testing.T) {
	fixtureSkill := "../../tests/fixtures/registry/kubernetes-deployer"
	var stdout, stderr bytes.Buffer
	code := RunProbe([]string{fixtureSkill, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected RunProbe to exit 0, got %d. Stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"skill_name": "kubernetes-deployer"`) {
		t.Errorf("expected json output with skill_name kubernetes-deployer, got:\n%s", stdout.String())
	}
}

func TestCLI_ProxyCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := RunProxy([]string{"serve", "--port", "9090", "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected RunProxy to exit 0, got %d. Stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"port": 9090`) {
		t.Errorf("expected json output with port 9090, got:\n%s", stdout.String())
	}
}

func TestCLI_TelemetryCommand(t *testing.T) {
	fixtureSkill := "../../tests/fixtures/registry/kubernetes-deployer"
	var stdout, stderr bytes.Buffer
	code := RunTelemetry([]string{"export", fixtureSkill, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected RunTelemetry to exit 0, got %d. Stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"service.name": "skil-agent-governance"`) {
		t.Errorf("expected json output with service.name, got:\n%s", stdout.String())
	}
}
