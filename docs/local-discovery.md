# Local component discovery

```
skil discover [--home dir] [--format terminal|json] [--output file]
```

`skil discover` answers a different question than `skil scan-all <collection>`:
`scan-all` finds every skill *inside a directory the caller already pointed
it at*. `discover` instead inventories what AI-agent skill and MCP-server
components are already installed on the local machine, in the well-known
per-tool locations several popular coding-agent tools use — without the
caller specifying a project directory at all.

Discovery is read-only and never executes anything. Skill-tree locations
(e.g. `~/.claude/skills`) are walked for `SKILL.md` files, reading only far
enough into the frontmatter to extract a display name. MCP-config
locations (e.g. `claude_desktop_config.json`) are parsed as JSON to extract
each declared server's name, command, and arguments — exactly the same
static, untrusted metadata `SKIL-MCP-*` rules already treat with suspicion,
reported here as-is. Discovery makes no decision about any of it: the
operator reviews the inventory and explicitly runs `skil scan <skill>` or
`skil mcp assure <skill> --runtime-command ...` on whatever they choose to
actually analyze.

## Coverage

A fixed, documented, best-effort catalog — not a claim of exhaustive
coverage of every agent tool that exists:

| Tool | Location | What's extracted |
| --- | --- | --- |
| Claude Code | `~/.claude/skills/**/SKILL.md` | Installed skills |
| Claude Code | `~/.claude.json` (`mcpServers`) | Declared MCP servers |
| Claude Desktop | `claude_desktop_config.json` (`mcpServers`), OS-conventional path | Declared MCP servers |
| Cursor | `~/.cursor/mcp.json` (`mcpServers`) | Declared MCP servers |
| VS Code | `User/mcp.json` (`servers`), OS-conventional path | Declared MCP servers |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` (`mcpServers`) | Declared MCP servers |

A location that doesn't exist on a given machine is silently skipped, not
an error — most machines will only have a few of the covered tools
installed. A config file that exists but isn't valid JSON, or isn't shaped
like an MCP config, is likewise treated as absent rather than a hard
failure, so one malformed file never hides everything else discovery
found. A symlinked config file or skill-tree root is never followed.

## Example

```
$ skil discover

LOCAL COMPONENT DISCOVERY

Home: /home/alice
Found: 2 component(s)

Nothing listed here has been executed or scanned — run `skil scan` or
`skil mcp assure` explicitly on anything below to actually analyze it.

claude-code
  [mcp_server] filesystem: npx [-y @modelcontextprotocol/server-filesystem /tmp] (declared in /home/alice/.claude.json)
  [skill]      repo-review (/home/alice/.claude/skills/repo-review)
```

`--home` overrides the home/profile directory probed (default: the current
user's, resolved the same way `os.UserHomeDir()` does) — useful for
inspecting a different user's profile snapshot, or in a test/CI context
where `$HOME` doesn't reflect a real workstation.
