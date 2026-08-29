package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

// AgentExecutionSurface captures normalized lifecycle hooks, permissions,
// model boundaries, and subagent delegations declared in agent configuration
// files (.claude/settings.json, .claude/hooks.json, hooks/hooks.json,
// .cursor/, .vscode/, .codex/, .opencode/, .kiro/).
type AgentExecutionSurface struct {
	AgentType   string            `json:"agent_type"`
	SourceFile  string            `json:"source_file"`
	Hooks       []AgentHook       `json:"hooks,omitempty"`
	Permissions []AgentPermission `json:"permissions,omitempty"`
}

type AgentHook struct {
	Event       string   `json:"event"`        // SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, PermissionRequest, SubagentStart, SubagentStop
	HandlerType string   `json:"handler_type"` // command, http, mcp, subagent
	Command     []string `json:"command,omitempty"`
	URL         string   `json:"url,omitempty"`
	MCPTool     string   `json:"mcp_tool,omitempty"`
	Agent       string   `json:"agent,omitempty"`
	Matcher     string   `json:"matcher,omitempty"`
	Conditional bool     `json:"conditional,omitempty"`
}

type AgentPermission struct {
	Scope      string `json:"scope"` // filesystem, network, shell, tools, bypass
	Path       string `json:"path,omitempty"`
	Mode       string `json:"mode,omitempty"`
	IsBypass   bool   `json:"is_bypass,omitempty"`
	IsWildcard bool   `json:"is_wildcard,omitempty"`
}

type AgentExecutionSurfaceAnalyzer struct{}

func NewAgentExecutionSurface() *AgentExecutionSurfaceAnalyzer {
	return &AgentExecutionSurfaceAnalyzer{}
}

func (a *AgentExecutionSurfaceAnalyzer) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.agent-execution-surface", Version: "1.0.0",
		Domain: "agent-execution", Subdomain: "lifecycle-hooks",
		Categories:     []string{"agent-execution", "privilege-escalation"},
		AnalysisTypes:  []string{"agent-execution"},
		SupportedTypes: []string{"json"},
	}
}

func (a *AgentExecutionSurfaceAnalyzer) Rules() []skil.Rule {
	return []skil.Rule{
		{
			ID: "SKIL-AGENT-HOOK-001", Title: "Dangerous shell command hook in agent lifecycle", Category: "agent-execution",
			Severity: skil.SeverityHigh, Analysis: "agent-execution", AppliesTo: []string{"json", "toml", "yaml", "yml"},
			Description: "An agent configuration declares a lifecycle hook that executes arbitrary shell commands.",
			Remediation: "Avoid arbitrary shell execution in lifecycle hooks or pin the hook binary to a reviewed, read-only helper.",
		},
		{
			ID: "SKIL-AGENT-HOOK-002", Title: "Exfiltration flow from sensitive agent event to remote endpoint", Category: "agent-execution",
			Severity: skil.SeverityCritical, Analysis: "agent-execution", AppliesTo: []string{"json", "toml", "yaml", "yml"},
			Description: "An agent lifecycle hook routes sensitive event data (user prompt, tool input/output, credentials) to a remote HTTP destination.",
			Remediation: "Ensure lifecycle hooks never send prompt context or credentials to remote endpoints without explicit user consent.",
		},
		{
			ID: "SKIL-AGENT-HOOK-003", Title: "Unreviewed MCP tool call in agent hook", Category: "agent-execution",
			Severity: skil.SeverityHigh, Analysis: "agent-execution", AppliesTo: []string{"json", "toml", "yaml", "yml"},
			Description: "An agent hook invokes an MCP tool directly upon lifecycle events, bypassing interactive user prompt review.",
			Remediation: "Require interactive user confirmation before triggering side-effecting MCP tools from hooks.",
		},
		{
			ID: "SKIL-AGENT-PERM-001", Title: "Agent permission bypass mode enabled", Category: "privilege-escalation",
			Severity: skil.SeverityCritical, Analysis: "agent-execution", AppliesTo: []string{"json", "toml", "yaml", "yml"},
			Description: "Agent configuration explicitly enables bypass permissions (e.g. bypassPermissions: true or autoApprove: ['*']).",
			Remediation: "Disable permission bypass mode and use explicit, least-privilege tool approval rules.",
		},
		{
			ID: "SKIL-AGENT-PERM-002", Title: "Sensitive directory access granted to agent", Category: "privilege-escalation",
			Severity: skil.SeverityHigh, Analysis: "agent-execution", AppliesTo: []string{"json", "toml", "yaml", "yml"},
			Description: "Agent configuration grants write or read access to sensitive credential locations (~/.ssh, ~/.aws, ~/.kube, ~/.config/gcloud, ~/.docker, ~/.npmrc, ~/.netrc).",
			Remediation: "Exclude sensitive credential and key directories from agent access scopes.",
		},
		{
			ID: "SKIL-AGENT-PERM-003", Title: "Broad wildcard permission granted to agent", Category: "privilege-escalation",
			Severity: skil.SeverityHigh, Analysis: "agent-execution", AppliesTo: []string{"json"},
			Description: "Agent configuration grants a wildcard shell, filesystem, network, or tool capability.",
			Remediation: "Replace wildcard permissions with the smallest explicit operation and target allowlist.",
		},
	}
}

var sensitiveDirectories = []string{
	".ssh", ".aws", ".kube", ".config/gcloud", ".docker", ".npmrc", ".netrc", ".gnupg",
}

func (a *AgentExecutionSurfaceAnalyzer) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	findings, _, err := a.AnalyzeCapabilities(ctx, ac)
	return findings, err
}

func (a *AgentExecutionSurfaceAnalyzer) AnalyzeCapabilities(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, []skil.CapabilityObservation, error) {
	var findings []skil.Finding
	var observations []skil.CapabilityObservation

	for _, file := range ac.Artifact.Files {
		if !isAgentConfigFile(file.Path) {
			continue
		}

		surface, err := parseAgentConfigFile(file)
		if err != nil {
			return nil, nil, fmt.Errorf("parse agent execution config %s: %w", file.Path, err)
		}

		// Emit capability observations and findings
		for _, hook := range surface.Hooks {
			line, text := lineContaining(file.Data, hook.Event)
			if line == 0 {
				line = 1
			}

			switch hook.HandlerType {
			case "command":
				cmdStr := strings.Join(hook.Command, " ")
				observations = append(observations, skil.CapabilityObservation{
					Capability: "hook.execute.command", Value: cmdStr,
					Location: skil.Location{File: file.Path, StartLine: line, EndLine: line},
					Analyzer: "builtin.agent-execution-surface",
				})
				if isSensitiveEvent(hook.Event) && containsRemoteURL(cmdStr) {
					finding := makeFinding(RulePattern{Rule: a.ruleByID("SKIL-AGENT-HOOK-002"), Confidence: .95}, file, line, text)
					finding.Evidence["event"] = hook.Event
					finding.Evidence["command"] = cmdStr
					findings = append(findings, finding)
				} else if isDangerousCommand(cmdStr) {
					findings = append(findings, makeFinding(RulePattern{Rule: a.ruleByID("SKIL-AGENT-HOOK-001"), Confidence: .95}, file, line, text))
				}
			case "http":
				observations = append(observations, skil.CapabilityObservation{
					Capability: "hook.call.http", Value: hook.URL,
					Location: skil.Location{File: file.Path, StartLine: line, EndLine: line},
					Analyzer: "builtin.agent-execution-surface",
				})
				if isSensitiveEvent(hook.Event) {
					finding := makeFinding(RulePattern{Rule: a.ruleByID("SKIL-AGENT-HOOK-002"), Confidence: .95}, file, line, text)
					finding.Evidence["event"] = hook.Event
					finding.Evidence["destination_url"] = hook.URL
					findings = append(findings, finding)
				}
			case "mcp":
				observations = append(observations, skil.CapabilityObservation{
					Capability: "hook.call.mcp", Value: hook.MCPTool,
					Location: skil.Location{File: file.Path, StartLine: line, EndLine: line},
					Analyzer: "builtin.agent-execution-surface",
				})
				findings = append(findings, makeFinding(RulePattern{Rule: a.ruleByID("SKIL-AGENT-HOOK-003"), Confidence: .90}, file, line, text))
			case "subagent":
				observations = append(observations, skil.CapabilityObservation{
					Capability: "hook.invoke.agent", Value: hook.Agent,
					Location: skil.Location{File: file.Path, StartLine: line, EndLine: line},
					Analyzer: "builtin.agent-execution-surface",
				})
			}
		}

		for _, perm := range surface.Permissions {
			line, text := lineContaining(file.Data, perm.Scope)
			if line == 0 {
				line = 1
			}
			if perm.Mode == "deny" {
				continue
			}

			if perm.IsBypass {
				observations = append(observations, skil.CapabilityObservation{
					Capability: "permission.bypass", Value: perm.Scope,
					Location: skil.Location{File: file.Path, StartLine: line, EndLine: line},
					Analyzer: "builtin.agent-execution-surface",
				})
				findings = append(findings, makeFinding(RulePattern{Rule: a.ruleByID("SKIL-AGENT-PERM-001"), Confidence: .98}, file, line, text))
			}

			capability := permissionCapability(perm)
			if capability != "" && !perm.IsBypass {
				observations = append(observations, skil.CapabilityObservation{
					Capability: capability, Value: perm.Path,
					Location: skil.Location{File: file.Path, StartLine: line, EndLine: line},
					Analyzer: "builtin.agent-execution-surface",
					Evidence: map[string]any{"mode": perm.Mode, "wildcard": perm.IsWildcard},
				})
			}
			if perm.IsWildcard && perm.Mode == "allow" {
				finding := makeFinding(RulePattern{Rule: a.ruleByID("SKIL-AGENT-PERM-003"), Confidence: .98}, file, line, text)
				finding.Evidence["scope"] = perm.Scope
				finding.Evidence["permission"] = perm.Path
				findings = append(findings, finding)
			}

			if isSensitivePath(perm.Path) {
				finding := makeFinding(RulePattern{Rule: a.ruleByID("SKIL-AGENT-PERM-002"), Confidence: .95}, file, line, text)
				finding.Evidence["sensitive_path"] = perm.Path
				findings = append(findings, finding)
			}
		}
	}

	return findings, observations, nil
}

func (a *AgentExecutionSurfaceAnalyzer) ruleByID(id string) skil.Rule {
	for _, r := range a.Rules() {
		if r.ID == id {
			return r
		}
	}
	return skil.Rule{ID: id}
}

func isAgentConfigFile(path string) bool {
	clean := filepath.ToSlash(strings.ToLower(path))
	return strings.Contains(clean, ".claude/") ||
		strings.Contains(clean, ".cursor/") ||
		strings.Contains(clean, ".vscode/") ||
		strings.Contains(clean, ".codex/") ||
		strings.Contains(clean, ".opencode/") ||
		strings.Contains(clean, ".kiro/") ||
		strings.HasSuffix(clean, "hooks/hooks.json") ||
		strings.HasSuffix(clean, "hooks.json")
}

func isSensitiveEvent(event string) bool {
	e := strings.ToLower(event)
	return strings.Contains(e, "prompt") ||
		strings.Contains(e, "user") ||
		strings.Contains(e, "credential") ||
		strings.Contains(e, "pretool") ||
		strings.Contains(e, "posttool")
}

func containsRemoteURL(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "http://") || strings.Contains(l, "https://")
}

func isDangerousCommand(cmd string) bool {
	c := strings.ToLower(cmd)
	return strings.Contains(c, "curl ") ||
		strings.Contains(c, "wget ") ||
		strings.Contains(c, "bash ") ||
		strings.Contains(c, "sh ") ||
		strings.Contains(c, "nc ") ||
		strings.Contains(c, "eval") ||
		strings.Contains(c, "python ")
}

func isSensitivePath(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	for _, sens := range sensitiveDirectories {
		if strings.Contains(p, sens) {
			return true
		}
	}
	return false
}

func parseAgentConfigFile(file skil.File) (*AgentExecutionSurface, error) {
	var raw map[string]any
	if err := json.Unmarshal(file.Data, &raw); err != nil {
		return nil, err
	}

	surface := &AgentExecutionSurface{
		SourceFile: file.Path,
		AgentType:  detectAgentType(file.Path),
	}

	// Check permission bypass
	if bypass, ok := raw["bypassPermissions"].(bool); ok && bypass {
		surface.Permissions = append(surface.Permissions, AgentPermission{
			Scope: "all", IsBypass: true,
		})
	}
	if autoApprove, ok := raw["autoApprove"].([]any); ok {
		for _, item := range autoApprove {
			if str, ok := item.(string); ok && str == "*" {
				surface.Permissions = append(surface.Permissions, AgentPermission{
					Scope: "autoApprove", IsBypass: true,
				})
			}
		}
	}

	// Check filesystem permissions
	if permissions, ok := raw["permissions"].(map[string]any); ok {
		if mode, _ := permissions["defaultMode"].(string); strings.EqualFold(mode, "bypassPermissions") {
			surface.Permissions = append(surface.Permissions, AgentPermission{Scope: "defaultMode", Mode: mode, IsBypass: true})
		}
		if fs, ok := permissions["filesystem"].([]any); ok {
			for _, item := range fs {
				if pathStr, ok := item.(string); ok {
					surface.Permissions = append(surface.Permissions, AgentPermission{
						Scope: "filesystem", Path: pathStr, Mode: "rw",
					})
				}
			}
		}
		for _, field := range []string{"allow", "deny", "ask"} {
			items, _ := permissions[field].([]any)
			for _, item := range items {
				if value, ok := item.(string); ok {
					surface.Permissions = append(surface.Permissions, normalizeClaudePermission(field, value))
				}
			}
		}
		if dirs, ok := permissions["additionalDirectories"].([]any); ok {
			for _, item := range dirs {
				if value, ok := item.(string); ok {
					surface.Permissions = append(surface.Permissions, AgentPermission{Scope: "filesystem", Path: value, Mode: "read"})
				}
			}
		}
	}

	// Parse hooks
	if hooksRaw, ok := raw["hooks"].(map[string]any); ok {
		for event, handlerVal := range hooksRaw {
			surface.Hooks = append(surface.Hooks, parseHooks(event, handlerVal, "")...)
		}
	} else if hooksList, ok := raw["hooks"].([]any); ok {
		for _, item := range hooksList {
			if hookMap, ok := item.(map[string]any); ok {
				event, _ := hookMap["event"].(string)
				hook := parseHook(event, hookMap)
				if hook != nil {
					surface.Hooks = append(surface.Hooks, *hook)
				}
			}
		}
	}
	sort.Slice(surface.Hooks, func(i, j int) bool {
		a, b := surface.Hooks[i], surface.Hooks[j]
		return a.Event+"\x00"+a.Matcher+"\x00"+a.HandlerType+"\x00"+strings.Join(a.Command, "\x00")+a.URL+a.MCPTool+a.Agent <
			b.Event+"\x00"+b.Matcher+"\x00"+b.HandlerType+"\x00"+strings.Join(b.Command, "\x00")+b.URL+b.MCPTool+b.Agent
	})
	sort.Slice(surface.Permissions, func(i, j int) bool {
		a, b := surface.Permissions[i], surface.Permissions[j]
		return a.Scope+"\x00"+a.Mode+"\x00"+a.Path < b.Scope+"\x00"+b.Mode+"\x00"+b.Path
	})

	return surface, nil
}

func parseHooks(event string, value any, inheritedMatcher string) []AgentHook {
	if hook := parseHook(event, value); hook != nil {
		hook.Matcher = inheritedMatcher
		return []AgentHook{*hook}
	}
	var out []AgentHook
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			out = append(out, parseHooks(event, item, inheritedMatcher)...)
		}
	case map[string]any:
		matcher := inheritedMatcher
		if value, ok := typed["matcher"].(string); ok {
			matcher = value
		}
		if nested, ok := typed["hooks"]; ok {
			out = append(out, parseHooks(event, nested, matcher)...)
		}
	}
	return out
}

func parseHook(event string, val any) *AgentHook {
	switch v := val.(type) {
	case string:
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			return &AgentHook{Event: event, HandlerType: "http", URL: v}
		}
		return &AgentHook{Event: event, HandlerType: "command", Command: strings.Fields(v)}
	case map[string]any:
		hook := &AgentHook{Event: event}
		typeName, _ := v["type"].(string)
		if cmd, ok := v["command"].(string); ok && (typeName == "" || typeName == "command") {
			hook.HandlerType = "command"
			hook.Command = strings.Fields(cmd)
		} else if cmdArr, ok := v["command"].([]any); ok {
			hook.HandlerType = "command"
			for _, item := range cmdArr {
				if s, ok := item.(string); ok {
					hook.Command = append(hook.Command, s)
				}
			}
		} else if urlStr, ok := v["url"].(string); ok {
			hook.HandlerType = "http"
			hook.URL = urlStr
		} else if mcpTool, ok := v["mcp_tool"].(string); ok {
			hook.HandlerType = "mcp"
			hook.MCPTool = mcpTool
		} else if subagent, ok := v["agent"].(string); ok {
			hook.HandlerType = "subagent"
			hook.Agent = subagent
		}
		if hook.HandlerType != "" {
			return hook
		}
	}
	return nil
}

func normalizeClaudePermission(mode, value string) AgentPermission {
	permission := AgentPermission{Mode: mode, Path: value, IsWildcard: strings.Contains(value, "*")}
	name, argument := value, ""
	if open := strings.IndexByte(value, '('); open >= 0 && strings.HasSuffix(value, ")") {
		name, argument = value[:open], strings.TrimSuffix(value[open+1:], ")")
	}
	permission.Path = argument
	switch strings.ToLower(name) {
	case "bash", "shell":
		permission.Scope = "shell"
	case "read", "glob", "grep":
		permission.Scope = "filesystem.read"
	case "write", "edit", "notebookedit":
		permission.Scope = "filesystem.write"
	case "webfetch", "websearch":
		permission.Scope = "network"
	default:
		permission.Scope = "tools"
		if permission.Path == "" {
			permission.Path = value
		}
	}
	return permission
}

func permissionCapability(permission AgentPermission) string {
	if permission.Mode == "deny" {
		return ""
	}
	switch permission.Scope {
	case "shell":
		return "permission.shell"
	case "network":
		return "permission.network"
	case "filesystem.read":
		return "permission.filesystem.read"
	case "filesystem.write", "filesystem":
		if permission.Mode == "read" {
			return "permission.filesystem.read"
		}
		return "permission.filesystem.write"
	case "tools":
		return "permission.tools"
	default:
		return ""
	}
}

func detectAgentType(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, ".claude"):
		return "claude"
	case strings.Contains(p, ".cursor"):
		return "cursor"
	case strings.Contains(p, ".vscode"):
		return "vscode"
	case strings.Contains(p, ".codex"):
		return "codex"
	case strings.Contains(p, ".opencode"):
		return "opencode"
	case strings.Contains(p, ".kiro"):
		return "kiro"
	default:
		return "generic-agent"
	}
}

// ComputeSurfaceDigest computes a canonical SHA-256 digest over an AgentExecutionSurface.
func (s *AgentExecutionSurface) ComputeSurfaceDigest() (string, error) {
	data, err := signing.CanonicalJSON(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
