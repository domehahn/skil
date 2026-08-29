package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/domehahn/skil/internal/artifact"
)

// WorkspaceLocation describes one project-scoped configuration directory or file to probe.
type WorkspaceLocation struct {
	Tool    string
	Kind    locationKind
	RelPath string
	Format  configFormat
}

func WorkspaceLocations() []WorkspaceLocation {
	return []WorkspaceLocation{
		{Tool: "claude-code", Kind: skillTree, RelPath: ".claude/skills"},
		{Tool: "claude-code", Kind: mcpConfig, RelPath: ".claude/mcp.json", Format: formatStandard},
		{Tool: "claude-code", Kind: mcpConfig, RelPath: ".claude/settings.json", Format: formatStandard},
		{Tool: "cursor", Kind: skillTree, RelPath: ".cursor/skills"},
		{Tool: "cursor", Kind: mcpConfig, RelPath: ".cursor/mcp.json", Format: formatStandard},
		{Tool: "cursor", Kind: mcpConfig, RelPath: ".cursor/settings.json", Format: formatStandard},
		{Tool: "vscode", Kind: mcpConfig, RelPath: ".vscode/mcp.json", Format: formatStandard},
		{Tool: "vscode", Kind: mcpConfig, RelPath: ".vscode/settings.json", Format: formatStandard},
		{Tool: "codex", Kind: skillTree, RelPath: ".codex/skills"},
		{Tool: "codex", Kind: mcpConfig, RelPath: ".codex/config.toml", Format: formatCodexTOML},
		{Tool: "opencode", Kind: mcpConfig, RelPath: ".opencode/mcp.json", Format: formatOpenCode},
		{Tool: "kiro", Kind: mcpConfig, RelPath: ".kiro/mcp.json", Format: formatStandard},
		{Tool: "gemini", Kind: skillTree, RelPath: ".gemini/skills"},
		{Tool: "gemini", Kind: mcpConfig, RelPath: ".gemini/mcp.json", Format: formatStandard},
		{Tool: "gemini", Kind: mcpConfig, RelPath: ".gemini/settings.json", Format: formatStandard},
	}
}

// DiscoverWorkspace performs read-only, bounded discovery of agent tool components inside workspaceRoot.
func DiscoverWorkspace(workspaceRoot string) ([]Component, error) {
	cleanRoot := filepath.Clean(workspaceRoot)
	ingestor, err := artifact.NewSecureIngestor(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("init secure ingestor for workspace: %w", err)
	}

	var out []Component

	for _, loc := range WorkspaceLocations() {
		targetPath := filepath.Join(cleanRoot, loc.RelPath)
		info, err := os.Lstat(targetPath)
		if os.IsNotExist(err) || err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}

		switch loc.Kind {
		case skillTree:
			if !info.IsDir() {
				continue
			}
			components, _ := scanSkillTreePath(targetPath, loc.Tool)
			out = append(out, components...)

		case mcpConfig:
			if !info.Mode().IsRegular() {
				continue
			}
			data, _, err := ingestor.ReadFileSafely(loc.RelPath, maxConfigBytes)
			if err != nil {
				continue
			}
			components := parseMCPConfigData(data, targetPath, loc.Tool, loc.Format)
			out = append(out, components...)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Tool != out[j].Tool {
			return out[i].Tool < out[j].Tool
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Path < out[j].Path
	})

	return out, nil
}
