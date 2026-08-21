package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverFindsSkillsAndMCPServersUnderHome(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude", "skills", "repo-review"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "skills", "repo-review", "SKILL.md"), []byte("---\nname: repo-review\ndescription: Reviews a repository.\n---\n\nReview the repository.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "server"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{"discover", "--home", home, "--format", "json"})
	if code != ExitOK {
		t.Fatalf("discover failed: code=%d stderr=%s", code, stderr.String())
	}
	var result discoverResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parse discover JSON output: %v\n%s", err, stdout.String())
	}
	if result.Home != home || len(result.Components) != 2 {
		t.Fatalf("unexpected discover result: %#v", result)
	}
	var haveSkill, haveServer bool
	for _, component := range result.Components {
		if component.Name == "repo-review" && string(component.Kind) == "skill" {
			haveSkill = true
		}
		if component.Name == "filesystem" && string(component.Kind) == "mcp_server" && component.Command == "npx" {
			haveServer = true
		}
	}
	if !haveSkill || !haveServer {
		t.Fatalf("expected both a skill and an mcp server, got %#v", result.Components)
	}
}

func TestDiscoverEmptyHomeReportsNoComponents(t *testing.T) {
	home := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{"discover", "--home", home})
	if code != ExitOK {
		t.Fatalf("discover on an empty home should still succeed: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Found: 0 component(s)") {
		t.Fatalf("expected zero components reported, got:\n%s", stdout.String())
	}
}

func TestDiscoverRejectsExtraPositionalArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{"discover", "unexpected-arg"})
	if code != ExitInput {
		t.Fatalf("expected discover to reject a positional argument, got code=%d stderr=%s", code, stderr.String())
	}
}

func TestDiscoverRejectsUnsupportedFormat(t *testing.T) {
	home := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := New(&stdout, &stderr).Run(context.Background(), []string{"discover", "--home", home, "--format", "markdown"})
	if code != ExitInput || !strings.Contains(stderr.String(), "terminal or json") {
		t.Fatalf("expected discover to reject an unsupported format: code=%d stderr=%s", code, stderr.String())
	}
}
