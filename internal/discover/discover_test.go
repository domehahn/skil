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
		for _, want := range []string{
			"claude-code", "claude-desktop", "cursor", "vscode", "windsurf",
			"gemini-cli", "amazon-q", "kiro", "opencode", "codex-cli",
		} {
			if !tools[want] {
				t.Fatalf("%s: expected a location for tool %q, got %#v", goos, want, locations)
			}
		}
	}
}

func TestScanDiscoversGeminiCLIAmazonQAndKiroStandardShape(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".gemini", "settings.json"), `{
  "mcpServers": {"docs": {"command": "docs-server", "args": []}}
}`)
	writeFile(t, filepath.Join(home, ".aws", "amazonq", "mcp.json"), `{
  "mcpServers": {"weather": {"command": "/usr/local/bin/weather-mcp", "args": ["--port", "3000"]}}
}`)
	writeFile(t, filepath.Join(home, ".kiro", "settings", "mcp.json"), `{
  "mcpServers": {"aws-docs": {"command": "uvx", "args": ["aws-docs-mcp-server"]}}
}`)

	locations := KnownLocations(home, "linux")
	components, errs := Scan(locations)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	byTool := map[string]Component{}
	for _, c := range components {
		byTool[c.Tool] = c
	}
	if byTool["gemini-cli"].Name != "docs" || byTool["gemini-cli"].Command != "docs-server" {
		t.Fatalf("expected gemini-cli server 'docs', got %#v", byTool["gemini-cli"])
	}
	if byTool["amazon-q"].Name != "weather" || byTool["amazon-q"].Command != "/usr/local/bin/weather-mcp" {
		t.Fatalf("expected amazon-q server 'weather', got %#v", byTool["amazon-q"])
	}
	if byTool["kiro"].Name != "aws-docs" || byTool["kiro"].Command != "uvx" {
		t.Fatalf("expected kiro server 'aws-docs', got %#v", byTool["kiro"])
	}
}

func TestScanDiscoversOpenCodeArrayCommandShape(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".config", "opencode", "opencode.json"), `{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "my-local-mcp-server": {
      "type": "local",
      "command": ["npx", "-y", "my-mcp-command"],
      "enabled": true
    }
  }
}`)
	locations := KnownLocations(home, "linux")
	components, errs := Scan(locations)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(components) != 1 {
		t.Fatalf("expected exactly one opencode server, got %#v", components)
	}
	server := components[0]
	if server.Tool != "opencode" || server.Name != "my-local-mcp-server" ||
		server.Command != "npx" || len(server.Args) != 2 || server.Args[0] != "-y" || server.Args[1] != "my-mcp-command" {
		t.Fatalf("expected the array command split into command+args: %#v", server)
	}
}

func TestScanDiscoversCodexTOMLShape(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), `
[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]

[mcp_servers.context7.env]
MY_ENV_VAR = "MY_ENV_VALUE"
`)
	locations := KnownLocations(home, "linux")
	components, errs := Scan(locations)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(components) != 1 {
		t.Fatalf("expected exactly one codex server, got %#v", components)
	}
	server := components[0]
	if server.Tool != "codex-cli" || server.Name != "context7" || server.Command != "npx" ||
		len(server.Args) != 2 || server.Args[0] != "-y" {
		t.Fatalf("unexpected parsed codex server: %#v", server)
	}
}

func TestScanToleratesMalformedCodexTOMLWithoutError(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), "this is not [ valid toml =")
	locations := KnownLocations(home, "linux")
	components, errs := Scan(locations)
	if len(errs) != 0 {
		t.Fatalf("a malformed TOML file must be treated as absent, not an error: %v", errs)
	}
	if len(components) != 0 {
		t.Fatalf("expected no components from malformed TOML: %#v", components)
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
