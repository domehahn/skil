package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanDiscoversClaudeCodeSkillsAndMCPServers(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude", "skills", "repo-review", "SKILL.md"), `---
name: repo-review
description: Reviews a repository.
---

Review the repository.
`)
	writeFile(t, filepath.Join(home, ".claude.json"), `{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}
  }
}`)

	locations := KnownLocations(home, "linux")
	components, errs := Scan(locations)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	var skill, server *Component
	for i := range components {
		switch components[i].Kind {
		case KindSkill:
			skill = &components[i]
		case KindMCPServer:
			server = &components[i]
		}
	}
	if skill == nil || skill.Name != "repo-review" || skill.Tool != "claude-code" {
		t.Fatalf("expected claude-code skill 'repo-review', got %#v (all: %#v)", skill, components)
	}
	if server == nil || server.Name != "filesystem" || server.Command != "npx" || len(server.Args) != 3 {
		t.Fatalf("expected claude-code mcp server 'filesystem', got %#v (all: %#v)", server, components)
	}
}

func TestScanDiscoversVSCodeServersKeyShape(t *testing.T) {
	home := t.TempDir()
	// VS Code's mcp.json uses "servers", not "mcpServers".
	writeFile(t, filepath.Join(home, ".config", "Code", "User", "mcp.json"), `{
  "servers": {
    "github": {"command": "docker", "args": ["run", "-i", "ghcr.io/github/github-mcp-server"]}
  }
}`)

	locations := KnownLocations(home, "linux")
	components, errs := Scan(locations)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(components) != 1 || components[0].Name != "github" || components[0].Tool != "vscode" {
		t.Fatalf("expected one vscode mcp server 'github', got %#v", components)
	}
}

func TestScanIgnoresMissingLocationsWithoutError(t *testing.T) {
	home := t.TempDir() // nothing exists under this home at all
	locations := KnownLocations(home, "darwin")
	components, errs := Scan(locations)
	if len(errs) != 0 {
		t.Fatalf("a missing location must not be an error: %v", errs)
	}
	if len(components) != 0 {
		t.Fatalf("expected no components from an empty home: %#v", components)
	}
}

func TestScanToleratesMalformedConfigWithoutHidingOtherFindings(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude.json"), `{ not valid json`)
	writeFile(t, filepath.Join(home, ".cursor", "mcp.json"), `{
  "mcpServers": {"search": {"command": "search-server", "args": []}}
}`)

	locations := KnownLocations(home, "linux")
	components, errs := Scan(locations)
	if len(errs) != 0 {
		t.Fatalf("a malformed config file is reported as absent, not an error: %v", errs)
	}
	if len(components) != 1 || components[0].Name != "search" || components[0].Tool != "cursor" {
		t.Fatalf("malformed claude-code config must not hide cursor's valid one: %#v", components)
	}
}

func TestKnownLocationsPerOS(t *testing.T) {
	home := "/home/test"
	for _, goos := range []string{"darwin", "windows", "linux"} {
		locations := KnownLocations(home, goos)
		if len(locations) == 0 {
			t.Fatalf("%s: expected at least one known location", goos)
		}
		tools := map[string]bool{}
		for _, loc := range locations {
			tools[loc.Tool] = true
		}
		for _, want := range []string{"claude-code", "claude-desktop", "cursor", "vscode", "windsurf"} {
			if !tools[want] {
				t.Fatalf("%s: expected a location for tool %q, got %#v", goos, want, locations)
			}
		}
	}
}

func TestScanDoesNotFollowSymlinkedConfig(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(t.TempDir(), "secret.json")
	writeFile(t, real, `{"mcpServers": {"x": {"command": "x"}}}`)
	configPath := filepath.Join(home, ".claude.json")
	if err := os.Symlink(real, configPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	locations := KnownLocations(home, "linux")
	components, errs := Scan(locations)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(components) != 0 {
		t.Fatalf("expected a symlinked config to be ignored, got %#v", components)
	}
}

// TestComponentJSONShape locks the JSON field names so a CLI consumer's
// output format doesn't silently drift.
func TestComponentJSONShape(t *testing.T) {
	component := Component{Kind: KindMCPServer, Tool: "cursor", Name: "x", Path: "/p", Command: "cmd", Args: []string{"a"}}
	data, err := json.Marshal(component)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"kind", "tool", "name", "path", "command", "args"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("missing JSON key %q in %s", key, data)
		}
	}
}
