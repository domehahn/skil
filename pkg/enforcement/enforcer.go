package enforcement

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

type Enforcer struct {
	mu           sync.Mutex
	contract     skil.SkillContract
	started      time.Time
	toolCalls    int
	networkBytes int64
}

func New(contract skil.SkillContract) *Enforcer {
	return &Enforcer{contract: contract, started: time.Now()}
}

func (e *Enforcer) Authorize(operation skil.Operation) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if operation.Capability == "" {
		return errors.New("operation capability is required")
	}
	if limit := e.contract.Capabilities.Resources.MaxRuntimeSeconds; limit > 0 &&
		time.Since(e.started) > time.Duration(limit)*time.Second {
		return errors.New("maximum runtime exceeded")
	}
	if operation.Destructive && e.contract.Capabilities.Agent.ConfirmDestructive && !operation.Confirmed {
		return errors.New("destructive operation requires confirmation")
	}
	if operation.External && e.contract.Capabilities.Agent.ConfirmExternal && !operation.Confirmed {
		return errors.New("external operation requires confirmation")
	}
	if operation.External && !e.contract.Capabilities.Agent.ExternalSideEffects {
		return errors.New("external side effects are not allowed")
	}
	if err := e.authorizeCapability(operation); err != nil {
		return err
	}
	if operation.Capability == "tools.call" || operation.Capability == "mcp.tool" {
		if limit := e.contract.Capabilities.Resources.MaxToolCalls; limit > 0 && e.toolCalls+1 > limit {
			return errors.New("maximum tool call count exceeded")
		}
		e.toolCalls++
	}
	if operation.Capability == "network.outbound" {
		if operation.NetworkBytes < 0 {
			return errors.New("network byte count cannot be negative")
		}
		if limit := e.contract.Capabilities.Resources.MaxNetworkBytes; limit > 0 &&
			e.networkBytes+operation.NetworkBytes > limit {
			return errors.New("maximum network byte budget exceeded")
		}
		e.networkBytes += operation.NetworkBytes
	}
	return nil
}

func (e *Enforcer) authorizeCapability(operation skil.Operation) error {
	c := e.contract.Capabilities
	deny := func() error {
		return fmt.Errorf("%s target %q is not allowed by the skill contract", operation.Capability, operation.Target)
	}
	switch operation.Capability {
	case "filesystem.read":
		if !matchPath(operation.Target, c.Filesystem.Read) {
			return deny()
		}
	case "filesystem.write":
		if !matchPath(operation.Target, c.Filesystem.Write) {
			return deny()
		}
	case "filesystem.delete":
		if !matchPath(operation.Target, c.Filesystem.Delete) {
			return deny()
		}
	case "network.outbound":
		if !c.Network.Outbound || !matchHost(operation.Target, c.Network.Hosts) {
			return deny()
		}
	case "network.inbound":
		if !c.Network.Inbound {
			return deny()
		}
	case "commands.execute":
		if operation.Target != "" || !c.Commands.Execute || !matchCommand(operation.Command, c.Commands.Allow) {
			return deny()
		}
	case "secrets.read":
		if !contains(c.Secrets.Read, operation.Target) {
			return deny()
		}
	case "secrets.expose":
		if !c.Secrets.Expose {
			return deny()
		}
	case "environment.read":
		if !contains(c.Environment.Read, operation.Target) {
			return deny()
		}
	case "tools.call":
		if contains(c.Tools.Deny, operation.Target) || !contains(c.Tools.Allow, operation.Target) {
			return deny()
		}
	case "mcp.server":
		if !contains(c.MCP.Servers, operation.Target) {
			return deny()
		}
	case "mcp.tool":
		if !contains(c.MCP.Tools, operation.Target) {
			return deny()
		}
	case "persistence":
		if !c.Persistence {
			return deny()
		}
	case "agent.autonomous":
		if !c.Agent.AutonomousActions {
			return deny()
		}
	default:
		return fmt.Errorf("unknown capability %q", operation.Capability)
	}
	return nil
}

func matchPath(value string, patterns []string) bool {
	if value == "" || filepath.IsAbs(value) || strings.HasPrefix(filepath.ToSlash(value), "../") {
		return false
	}
	value = filepath.ToSlash(filepath.Clean(value))
	for _, pattern := range patterns {
		pattern = filepath.ToSlash(pattern)
		if ok, _ := filepath.Match(pattern, value); ok {
			return true
		}
		prefix := strings.TrimSuffix(pattern, "/**")
		if prefix != pattern && (value == prefix || strings.HasPrefix(value, prefix+"/")) {
			return true
		}
	}
	return false
}

func matchHost(value string, allowed []string) bool {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	for _, item := range allowed {
		item = strings.ToLower(strings.TrimSuffix(item, "."))
		if value == item || (strings.HasPrefix(item, "*.") && strings.HasSuffix(value, item[1:]) && value != item[2:]) {
			return true
		}
	}
	return false
}

func matchCommand(argv []string, allowed []string) bool {
	if len(argv) == 0 || argv[0] == "" {
		return false
	}
	for _, arg := range argv {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return false
		}
	}
	for _, item := range allowed {
		allowedFields := strings.Fields(item)
		if len(allowedFields) > 0 && len(argv) >= len(allowedFields) && slices.Equal(argv[:len(allowedFields)], allowedFields) {
			return true
		}
	}
	return false
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
