package policy

import (
	"fmt"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

// SynthesizeFromScan generates a minimal-privilege Policy tailored to an observed ScanResult.
func SynthesizeFromScan(scan skil.ScanResult, strict bool) (Policy, string, error) {
	pol := Policy{
		Version:         1,
		MaximumSeverity: string(scan.Maximum),
		RequireDigest:   true,
	}

	if pol.MaximumSeverity == "" {
		pol.MaximumSeverity = "HIGH"
	}

	// Completed analysis domains
	for domain, state := range scan.Coverage {
		if state == skil.CoverageCompleted {
			pol.RequiredAnalysis = append(pol.RequiredAnalysis, domain)
		}
	}

	// Inspect execution surface
	hasShellHook := false
	hasRemoteHook := false
	hasBypassPerm := false
	hasHooks := false

	for _, obs := range scan.Observations {
		if obs.Capability == "hook.execute.command" {
			hasShellHook = true
			hasHooks = true
		}
		if obs.Capability == "hook.call.http" {
			hasRemoteHook = true
			hasHooks = true
		}
		if obs.Capability == "permission.bypass" {
			hasBypassPerm = true
		}
	}

	for _, f := range scan.Findings {
		if f.RuleID == "SKIL-AGENT-HOOK-001" {
			hasShellHook = true
			hasHooks = true
		}
		if f.RuleID == "SKIL-AGENT-HOOK-002" {
			hasRemoteHook = true
			hasHooks = true
		}
		if f.RuleID == "SKIL-AGENT-PERM-001" {
			hasBypassPerm = true
		}
	}

	allowHooks := hasHooks
	allowShell := hasShellHook
	allowRemote := hasRemoteHook
	allowBypass := hasBypassPerm

	pol.AgentExecution = &AgentExecutionPolicy{
		AllowHooks:            &allowHooks,
		AllowShellHooks:       &allowShell,
		AllowRemoteHooks:      &allowRemote,
		AllowPermissionBypass: &allowBypass,
	}

	if strict {
		pol.RequireCompleteTransitiveClosure = true
		pol.DenyOpaqueExecutableContent = true
		pol.DenyBudgetExhausted = true
	}

	yamlBytes, err := yaml.Marshal(pol)
	if err != nil {
		return pol, "", fmt.Errorf("marshal synthesized policy: %w", err)
	}

	return pol, string(yamlBytes), nil
}
