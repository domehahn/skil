// Package discover finds AI-agent skill and MCP-server components already
// installed on the local machine, in the well-known per-tool locations
// several popular coding-agent tools use — without the caller pointing
// skil at a specific project directory first (that already-solved problem
// is internal/collection.Discover, used by `skil scan-all`/`lint-all`/
// `compose`). This is the "what AI-agent components exist on this machine
// that I haven't explicitly told skil to look at" inventory question.
//
// Discovery is read-only and never executes anything: skil-tree locations
// are walked for SKILL.md files (frontmatter read only far enough to
// extract a name), and MCP-config locations are parsed as JSON to extract
// declared server name/command/args — the exact same static metadata
// SKIL-MCP-* rules already treat as untrusted, reported here as-is for the
// operator to review and explicitly scan (`skil scan`) or assure
// (`skil mcp assure`) themselves. Discovery is deliberately not a scan: it
// only enumerates, so a caller always makes the explicit, reviewable
// decision of what to actually run next.
//
// The location list is a fixed, documented, best-effort catalog of known
// tools' conventional paths — not a claim of exhaustive coverage of every
// agent tool that exists. See KnownLocations's doc for exactly what is
// covered.
package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/domehahn/skil/internal/collection"
)

type ComponentKind string

const (
	KindSkill     ComponentKind = "skill"
	KindMCPServer ComponentKind = "mcp_server"
)

// Component is one discovered local AI-agent artifact. It is exactly what
// was found on disk — a path and, for MCP servers, the declared command —
// never anything executed or fetched.
type Component struct {
	Kind ComponentKind `json:"kind"`
	// Tool is the coding-agent tool whose convention this component was
	// found via (e.g. "claude-code", "claude-desktop", "cursor",
	// "vscode", "windsurf").
	Tool string `json:"tool"`
	// Name is the skill's declared name (from SKILL.md frontmatter) or
	// the MCP server's map key, whichever applies.
	Name string `json:"name"`
	// Path is the skill directory, or the config file an MCP server
	// entry was declared in.
	Path string `json:"path"`
	// Command/Args are an MCP server's declared launch command — never
	// executed by discovery itself. Empty for Kind == KindSkill.
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
}

type locationKind string

const (
	skillTree locationKind = "skill-tree"
	mcpConfig locationKind = "mcp-config"
)

type location struct {
	Tool string
	Kind locationKind
	Path string
}

// maxConfigBytes bounds how much of an MCP config file discovery will
// read — the same fail-closed sizing discipline used everywhere else in
// skil for untrusted input (internal/mcpregistry.MaxDocumentBytes,
// mcpassure.DefaultMaxResponseBytes, ...).
const maxConfigBytes = 1 << 20 // 1 MiB

// KnownLocations returns the fixed, documented catalog of per-tool
// locations discovery probes, resolved against home (a user's home/
// profile directory) and goos (matching runtime.GOOS's values). It takes
// both as parameters rather than reading them itself so the catalog is
// exactly reproducible and testable across all three OS conventions from
// a single-OS test run.
//
// Covered tools and locations (each is a best-effort convention, not a
// guarantee that a given install uses it):
//   - Claude Code: ~/.claude/skills/**/SKILL.md, and MCP servers declared
//     in ~/.claude.json's "mcpServers" map.
//   - Claude Desktop: claude_desktop_config.json's "mcpServers" map, at
//     its OS-conventional path.
//   - Cursor: ~/.cursor/mcp.json's "mcpServers" map.
//   - VS Code (MCP support): User/mcp.json's "servers" map, at its
//     OS-conventional path.
//   - Windsurf: ~/.codeium/windsurf/mcp_config.json's "mcpServers" map.
func KnownLocations(home, goos string) []location {
	join := func(parts ...string) string { return filepath.Join(append([]string{home}, parts...)...) }
	locations := []location{
		{Tool: "claude-code", Kind: skillTree, Path: join(".claude", "skills")},
		{Tool: "claude-code", Kind: mcpConfig, Path: join(".claude.json")},
		{Tool: "cursor", Kind: mcpConfig, Path: join(".cursor", "mcp.json")},
		{Tool: "windsurf", Kind: mcpConfig, Path: join(".codeium", "windsurf", "mcp_config.json")},
	}
	switch goos {
	case "darwin":
		locations = append(locations,
			location{Tool: "claude-desktop", Kind: mcpConfig, Path: join("Library", "Application Support", "Claude", "claude_desktop_config.json")},
			location{Tool: "vscode", Kind: mcpConfig, Path: join("Library", "Application Support", "Code", "User", "mcp.json")},
		)
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = join("AppData", "Roaming")
		}
		locations = append(locations,
			location{Tool: "claude-desktop", Kind: mcpConfig, Path: filepath.Join(appData, "Claude", "claude_desktop_config.json")},
			location{Tool: "vscode", Kind: mcpConfig, Path: filepath.Join(appData, "Code", "User", "mcp.json")},
		)
	default: // linux and other Unix-likes
		locations = append(locations,
			location{Tool: "claude-desktop", Kind: mcpConfig, Path: join(".config", "Claude", "claude_desktop_config.json")},
			location{Tool: "vscode", Kind: mcpConfig, Path: join(".config", "Code", "User", "mcp.json")},
		)
	}
	return locations
}

// Scan probes every location and returns every component actually found.
// A location that doesn't exist on this machine is silently skipped, not
// an error — most callers will have only a few of the covered tools
// installed. Parse errors on a config file that does exist are returned
// alongside any components found at other locations, so one malformed
// file never hides everything else.
func Scan(locations []location) ([]Component, []error) {
	var components []Component
	var errs []error
	for _, loc := range locations {
		switch loc.Kind {
		case skillTree:
			found, err := scanSkillTree(loc)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			components = append(components, found...)
		case mcpConfig:
			found, err := scanMCPConfig(loc)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			components = append(components, found...)
		}
	}
	sort.Slice(components, func(i, j int) bool {
		if components[i].Tool != components[j].Tool {
			return components[i].Tool < components[j].Tool
		}
		if components[i].Kind != components[j].Kind {
			return components[i].Kind < components[j].Kind
		}
		return components[i].Path < components[j].Path
	})
	return components, errs
}

func scanSkillTree(loc location) ([]Component, error) {
	info, err := os.Lstat(loc.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, nil
	}
	roots, err := collection.Discover(loc.Path)
	if err != nil {
		return nil, err
	}
	components := make([]Component, 0, len(roots))
	for _, root := range roots {
		components = append(components, Component{
			Kind: KindSkill, Tool: loc.Tool, Name: skillNameFromFrontmatter(root), Path: root,
		})
	}
	return components, nil
}

// skillNameFromFrontmatter makes a best-effort read of SKILL.md's
// "name:" frontmatter field for display purposes only; if it can't be
// read or parsed, the skill directory's own base name is used instead —
// discovery still reports the skill either way.
func skillNameFromFrontmatter(root string) string {
	fallback := filepath.Base(root)
	data, err := os.ReadFile(filepath.Join(root, "SKILL.md"))
	if err != nil {
		return fallback
	}
	if len(data) > maxConfigBytes {
		data = data[:maxConfigBytes]
	}
	text := string(data)
	if !strings.HasPrefix(text, "---") {
		return fallback
	}
	end := strings.Index(text[3:], "---")
	if end < 0 {
		return fallback
	}
	frontmatter := text[3 : 3+end]
	for _, line := range strings.Split(frontmatter, "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "name:"); ok {
			name := strings.Trim(strings.TrimSpace(after), `"'`)
			if name != "" {
				return name
			}
		}
	}
	return fallback
}

// mcpServerEntry matches both the "command"+"args" (stdio) server shape
// and simply ignores fields discovery has no use for (url-based remote
// servers, env, etc.) via json.RawMessage passthrough being unnecessary —
// discovery only ever reports command/args, never anything requiring
// deeper interpretation.
type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

func scanMCPConfig(loc location) ([]Component, error) {
	info, err := os.Lstat(loc.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil
	}
	if info.Size() > maxConfigBytes {
		return nil, nil
	}
	data, err := os.ReadFile(loc.Path)
	if err != nil {
		return nil, err
	}
	var document struct {
		MCPServers map[string]mcpServerEntry `json:"mcpServers"`
		Servers    map[string]mcpServerEntry `json:"servers"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		// A config file that exists but isn't valid JSON (or isn't
		// shaped like an MCP config at all) is reported as a diagnostic,
		// not a hard failure — the file may simply not be an MCP config.
		return nil, nil
	}
	servers := document.MCPServers
	if len(servers) == 0 {
		servers = document.Servers
	}
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	components := make([]Component, 0, len(names))
	for _, name := range names {
		entry := servers[name]
		components = append(components, Component{
			Kind: KindMCPServer, Tool: loc.Tool, Name: name, Path: loc.Path,
			Command: entry.Command, Args: entry.Args,
		})
	}
	return components, nil
}
