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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/domehahn/skil/internal/collection"
	"github.com/pelletier/go-toml/v2"
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
	Command        string   `json:"command,omitempty"`
	Args           []string `json:"args,omitempty"`
	Transport      string   `json:"transport,omitempty"`
	URL            string   `json:"url,omitempty"`
	TLSIdentity    string   `json:"tls_identity,omitempty"`
	AuthMode       string   `json:"auth_mode,omitempty"`
	SchemaDigest   string   `json:"schema_digest,omitempty"`
	IdentityDigest string   `json:"identity_digest,omitempty"`
}

type DiscoveryCoverageState string

const (
	DiscoveryComplete    DiscoveryCoverageState = "COMPLETE"
	DiscoveryPartial     DiscoveryCoverageState = "PARTIAL"
	DiscoveryUnsupported DiscoveryCoverageState = "UNSUPPORTED"
	DiscoveryFailed      DiscoveryCoverageState = "FAILED"
	DiscoveryNotPresent  DiscoveryCoverageState = "NOT_PRESENT"
)

type DiscoveryCoverage struct {
	Tool        string                 `json:"tool"`
	Path        string                 `json:"path"`
	State       DiscoveryCoverageState `json:"state"`
	Discovered  int                    `json:"discovered"`
	Limitations []string               `json:"limitations,omitempty"`
}

// AgentConfigAdapter makes vendor dialect ownership explicit. Adapters only
// locate and normalize configuration; they never execute declared commands.
type AgentConfigAdapter interface {
	ID() string
	Locations(home, goos string) []location
	Detect(path string, data []byte) bool
	ParseMCP(path string, data []byte) ([]Component, []string)
	Normalize(Component) Component
}

type locationKind string

const (
	skillTree locationKind = "skill-tree"
	mcpConfig locationKind = "mcp-config"
)

// configFormat selects which shape scanMCPConfig parses a mcpConfig
// location as. formatStandard covers every tool whose config uses the
// now-common "mcpServers"/"servers" map of {command, args} objects
// (Claude Code/Desktop, Cursor, Windsurf, VS Code, Gemini CLI, Amazon Q,
// Kiro); formatOpenCode and formatCodexTOML exist because those two tools
// each use a genuinely different shape (see their doc comments below).
type configFormat string

const (
	formatStandard  configFormat = ""
	formatOpenCode  configFormat = "opencode-json"
	formatCodexTOML configFormat = "codex-toml"
)

type location struct {
	Tool   string
	Kind   locationKind
	Path   string
	Format configFormat
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
// guarantee that a given install uses it; verified against each tool's own
// published documentation, not assumed from family resemblance):
//   - Claude Code: ~/.claude/skills/**/SKILL.md, and MCP servers declared
//     in ~/.claude.json's "mcpServers" map.
//   - Claude Desktop: claude_desktop_config.json's "mcpServers" map, at
//     its OS-conventional path.
//   - Cursor: ~/.cursor/mcp.json's "mcpServers" map.
//   - VS Code (MCP support): User/mcp.json's "servers" map, at its
//     OS-conventional path.
//   - Windsurf: ~/.codeium/windsurf/mcp_config.json's "mcpServers" map.
//   - Gemini CLI: ~/.gemini/settings.json's "mcpServers" map.
//   - Amazon Q Developer CLI: ~/.aws/amazonq/mcp.json's "mcpServers" map
//     (the global config; its workspace-scoped .amazonq/mcp.json is a
//     project-local file, out of scope for this home-directory-wide
//     discovery, matching the same scope boundary already drawn for
//     Claude Code's own project-local .mcp.json).
//   - Kiro: ~/.kiro/settings/mcp.json's "mcpServers" map.
//   - OpenCode: ~/.config/opencode/opencode.json (or ~/.opencode.json,
//     both documented as valid global locations) — a genuinely different
//     shape from every tool above: top-level key "mcp", and each entry's
//     command is a single array (["npx", "-y", "..."]) rather than a
//     separate command/args pair. See formatOpenCode.
//   - Codex CLI: ~/.codex/config.toml's "[mcp_servers.<name>]" tables —
//     TOML, not JSON. See formatCodexTOML.
func KnownLocations(home, goos string) []location {
	join := func(parts ...string) string { return filepath.Join(append([]string{home}, parts...)...) }
	locations := []location{
		{Tool: "claude-code", Kind: skillTree, Path: join(".claude", "skills")},
		{Tool: "claude-code", Kind: mcpConfig, Path: join(".claude.json")},
		{Tool: "cursor", Kind: mcpConfig, Path: join(".cursor", "mcp.json")},
		{Tool: "windsurf", Kind: mcpConfig, Path: join(".codeium", "windsurf", "mcp_config.json")},
		{Tool: "gemini-cli", Kind: mcpConfig, Path: join(".gemini", "settings.json")},
		{Tool: "amazon-q", Kind: mcpConfig, Path: join(".aws", "amazonq", "mcp.json")},
		{Tool: "kiro", Kind: mcpConfig, Path: join(".kiro", "settings", "mcp.json")},
		{Tool: "opencode", Kind: mcpConfig, Path: join(".config", "opencode", "opencode.json"), Format: formatOpenCode},
		{Tool: "opencode", Kind: mcpConfig, Path: join(".opencode.json"), Format: formatOpenCode},
		{Tool: "codex-cli", Kind: mcpConfig, Path: join(".codex", "config.toml"), Format: formatCodexTOML},
		{Tool: "github-copilot-cli", Kind: mcpConfig, Path: join(".copilot", "mcp-config.json")},
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
	components, _, errs := ScanWithCoverage(locations)
	return components, errs
}

// ScanWithCoverage preserves the difference between a missing configuration,
// a complete parse, and a present but malformed/unsupported dialect.
func ScanWithCoverage(locations []location) ([]Component, []DiscoveryCoverage, []error) {
	var components []Component
	var coverage []DiscoveryCoverage
	var errs []error
	for _, loc := range locations {
		entry := DiscoveryCoverage{Tool: loc.Tool, Path: loc.Path, State: DiscoveryNotPresent}
		switch loc.Kind {
		case skillTree:
			found, err := scanSkillTree(loc)
			if err != nil {
				errs = append(errs, err)
				entry.State, entry.Limitations = DiscoveryFailed, []string{err.Error()}
				coverage = append(coverage, entry)
				continue
			}
			if _, err := os.Lstat(loc.Path); err == nil {
				entry.State = DiscoveryComplete
			}
			entry.Discovered = len(found)
			coverage = append(coverage, entry)
			components = append(components, found...)
		case mcpConfig:
			found, state, limitations, err := scanMCPConfigCovered(loc)
			if err != nil {
				errs = append(errs, err)
				entry.State, entry.Limitations = DiscoveryFailed, []string{err.Error()}
				coverage = append(coverage, entry)
				continue
			}
			entry.State, entry.Limitations, entry.Discovered = state, limitations, len(found)
			coverage = append(coverage, entry)
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
	return components, coverage, errs
}

func scanSkillTree(loc location) ([]Component, error) {
	return scanSkillTreePath(loc.Path, loc.Tool)
}

func scanSkillTreePath(dir string, tool string) ([]Component, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, nil
	}
	roots, err := collection.Discover(dir)
	if err != nil {
		return nil, err
	}
	components := make([]Component, 0, len(roots))
	for _, root := range roots {
		components = append(components, Component{
			Kind: KindSkill, Tool: tool, Name: skillNameFromFrontmatter(root), Path: root,
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
	Command  string   `json:"command"`
	Args     []string `json:"args"`
	Type     string   `json:"type"`
	URL      string   `json:"url"`
	AuthMode string   `json:"authMode"`
}

func scanMCPConfig(loc location) ([]Component, error) {
	components, _, _, err := scanMCPConfigCovered(loc)
	return components, err
}

func scanMCPConfigCovered(loc location) ([]Component, DiscoveryCoverageState, []string, error) {
	info, err := os.Lstat(loc.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, DiscoveryNotPresent, nil, nil
		}
		return nil, DiscoveryFailed, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, DiscoveryUnsupported, []string{"configuration is not a regular non-symlink file"}, nil
	}
	if info.Size() > maxConfigBytes {
		return nil, DiscoveryUnsupported, []string{"configuration exceeds discovery byte limit"}, nil
	}
	data, err := os.ReadFile(loc.Path)
	if err != nil {
		return nil, DiscoveryFailed, nil, err
	}
	components, limitations := parseMCPConfigDataCovered(data, loc.Path, loc.Tool, loc.Format)
	state := DiscoveryComplete
	if len(limitations) > 0 {
		state = DiscoveryPartial
	}
	return components, state, limitations, nil
}

func parseMCPConfigData(data []byte, path string, tool string, format configFormat) []Component {
	res, _ := parseMCPConfigDataCovered(data, path, tool, format)
	return res
}

func parseMCPConfigDataCovered(data []byte, path string, tool string, format configFormat) ([]Component, []string) {
	loc := location{Path: path, Tool: tool, Format: format}
	var res []Component
	var err error
	switch format {
	case formatOpenCode:
		res, err = parseOpenCodeConfig(loc, data)
	case formatCodexTOML:
		res, err = parseCodexConfig(loc, data)
	default:
		return parseStandardMCPConfigCovered(loc, data)
	}
	if err != nil {
		return res, []string{err.Error()}
	}
	for i := range res {
		finalizeEndpoint(&res[i])
	}
	return res, nil
}

func parseStandardMCPConfig(loc location, data []byte) ([]Component, error) {
	components, limitations := parseStandardMCPConfigCovered(loc, data)
	if len(limitations) > 0 {
		return components, fmt.Errorf("%s", strings.Join(limitations, "; "))
	}
	return components, nil
}

func parseStandardMCPConfigCovered(loc location, data []byte) ([]Component, []string) {
	var document struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
		Servers    map[string]json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		// A config file that exists but isn't valid JSON (or isn't
		// shaped like an MCP config at all) is reported as a diagnostic,
		// not a hard failure — the file may simply not be an MCP config.
		return nil, []string{"malformed JSON: " + err.Error()}
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
	var limitations []string
	for _, name := range names {
		var entry mcpServerEntry
		if err := json.Unmarshal(servers[name], &entry); err != nil {
			limitations = append(limitations, "entry "+name+": "+err.Error())
			continue
		}
		transport := normalizeTransport(entry.Type, entry.Command, entry.URL)
		if transport == "UNKNOWN" {
			limitations = append(limitations, "entry "+name+": unknown transport "+entry.Type)
		}
		component := Component{
			Kind: KindMCPServer, Tool: loc.Tool, Name: name, Path: loc.Path,
			Command: entry.Command, Args: entry.Args, Transport: transport, URL: entry.URL, AuthMode: entry.AuthMode,
		}
		finalizeEndpoint(&component)
		components = append(components, component)
	}
	return components, limitations
}

func normalizeTransport(kind, command, endpoint string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "local", "stdio":
		if command != "" {
			return "STDIO"
		}
		if endpoint != "" {
			return "HTTP"
		}
		return "UNKNOWN"
	case "http":
		return "HTTP"
	case "sse":
		return "SSE"
	case "streamable_http", "streamable-http":
		return "STREAMABLE_HTTP"
	default:
		return "UNKNOWN"
	}
}

func finalizeEndpoint(c *Component) {
	if c.Kind != KindMCPServer {
		return
	}
	if c.Transport == "" {
		c.Transport = normalizeTransport("", c.Command, c.URL)
	}
	payload := struct {
		Tool, Path, Name, Transport, Command     string
		Args                                     []string
		URL, TLSIdentity, AuthMode, SchemaDigest string
	}{c.Tool, c.Path, c.Name, c.Transport, c.Command, c.Args, c.URL, c.TLSIdentity, c.AuthMode, c.SchemaDigest}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	c.IdentityDigest = "sha256:" + hex.EncodeToString(sum[:])
}

// openCodeServerEntry matches OpenCode's genuinely different shape: no
// separate command/args fields, only one array covering both (the
// executable is command[0], everything after is args).
type openCodeServerEntry struct {
	Type    string   `json:"type"`
	Command []string `json:"command"`
}

func parseOpenCodeConfig(loc location, data []byte) ([]Component, error) {
	var document struct {
		MCP map[string]openCodeServerEntry `json:"mcp"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(document.MCP))
	for name := range document.MCP {
		names = append(names, name)
	}
	sort.Strings(names)
	components := make([]Component, 0, len(names))
	for _, name := range names {
		entry := document.MCP[name]
		component := Component{Kind: KindMCPServer, Tool: loc.Tool, Name: name, Path: loc.Path}
		if len(entry.Command) > 0 {
			component.Command = entry.Command[0]
			component.Args = entry.Command[1:]
		}
		components = append(components, component)
	}
	for i := range components {
		finalizeEndpoint(&components[i])
	}
	return components, nil
}

// codexServerEntry matches Codex CLI's TOML "[mcp_servers.<name>]" table
// shape — the same command/args pair as the standard JSON tools, just in
// TOML rather than JSON.
type codexServerEntry struct {
	Command string   `toml:"command"`
	Args    []string `toml:"args"`
}

func parseCodexConfig(loc location, data []byte) ([]Component, error) {
	var document struct {
		MCPServers map[string]codexServerEntry `toml:"mcp_servers"`
	}
	if err := toml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(document.MCPServers))
	for name := range document.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)
	components := make([]Component, 0, len(names))
	for _, name := range names {
		entry := document.MCPServers[name]
		components = append(components, Component{
			Kind: KindMCPServer, Tool: loc.Tool, Name: name, Path: loc.Path,
			Command: entry.Command, Args: entry.Args,
		})
	}
	for i := range components {
		finalizeEndpoint(&components[i])
	}
	return components, nil
}
