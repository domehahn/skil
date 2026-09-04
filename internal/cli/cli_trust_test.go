package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLITrustCommands(t *testing.T) {
	fixtureSkill := "../../tests/fixtures/registry/kubernetes-deployer"
	supersetSkill := "../../tests/fixtures/registry/superset-skill"

	// 1. Test skil trust
	t.Run("skil trust terminal", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunTrust([]string{fixtureSkill}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("Expected exit code 0 for skil trust, got %d (stderr: %s)", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "SKIL Skill Trust Assessment") {
			t.Errorf("Expected trust header in stdout, got: %s", stdout.String())
		}
	})

	t.Run("skil trust json", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunTrust([]string{fixtureSkill, "--format", "json"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("Expected exit code 0 for skil trust --format json, got %d", code)
		}
		if !strings.Contains(stdout.String(), `"trust_score"`) {
			t.Errorf("Expected JSON trust score output, got: %s", stdout.String())
		}
	})

	// 2. Test skil card
	t.Run("skil card markdown", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunCard([]string{fixtureSkill, "--format", "markdown"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("Expected exit code 0 for skil card --format markdown, got %d", code)
		}
		if !strings.Contains(stdout.String(), "# SKIL Skill Card") {
			t.Errorf("Expected Markdown Skill Card header, got: %s", stdout.String())
		}
	})

	// 3. Test skil optimize context
	t.Run("skil optimize context", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunOptimize([]string{"context", fixtureSkill}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("Expected exit code 0 for skil optimize context, got %d", code)
		}
		if !strings.Contains(stdout.String(), "Context Efficiency Analysis") {
			t.Errorf("Expected context efficiency header, got: %s", stdout.String())
		}
	})

	// 4. Test skil graph
	t.Run("skil graph capabilities", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunGraph([]string{"capabilities", fixtureSkill}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("Expected exit code 0 for skil graph capabilities, got %d", code)
		}
		if !strings.Contains(stdout.String(), "SKIL Capability Graph") {
			t.Errorf("Expected capability graph header, got: %s", stdout.String())
		}
	})

	t.Run("skil graph attack-path", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunGraph([]string{"attack-path", fixtureSkill}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("Expected exit code 0 for skil graph attack-path, got %d", code)
		}
		if !strings.Contains(stdout.String(), "Cross-Skill Attack Path Graph") {
			t.Errorf("Expected attack path graph header, got: %s", stdout.String())
		}
	})

	// 5. Test skil compare
	t.Run("skil compare", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunCompare([]string{fixtureSkill, supersetSkill}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("Expected exit code 0 for skil compare, got %d", code)
		}
		if !strings.Contains(stdout.String(), "Version Comparison & Drift Analysis") {
			t.Errorf("Expected drift comparison header, got: %s", stdout.String())
		}
	})
}
