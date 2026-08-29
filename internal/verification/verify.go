package verification

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// capabilityMismatchRuleID identifies findings produced by Findings() below.
// Infer() must treat this rule ID as opaque verification output, never as
// raw capability evidence, to avoid feeding verification results back into
// verification input.
const capabilityMismatchRuleID = "SKIL-CAP-001"

type Mismatch struct {
	Capability string        `json:"capability" yaml:"capability"`
	Kind       string        `json:"kind" yaml:"kind"`
	Declared   any           `json:"declared" yaml:"declared"`
	Observed   bool          `json:"observed" yaml:"observed"`
	Severity   skil.Severity `json:"severity" yaml:"severity"`
	Evidence   []string      `json:"evidence" yaml:"evidence"`
}
type Result struct {
	Status     skil.Status               `json:"status" yaml:"status"`
	Declared   skil.Capabilities         `json:"declared" yaml:"declared"`
	Observed   skil.ObservedCapabilities `json:"observed" yaml:"observed"`
	Mismatches []Mismatch                `json:"mismatches" yaml:"mismatches"`
}

func Verify(contract skil.SkillContract, findings []skil.Finding, observations []skil.CapabilityObservation) Result {
	observed := Infer(findings, observations)
	result := Result{Status: skil.StatusPass, Declared: contract.Capabilities, Observed: observed, Mismatches: []Mismatch{}}
	check := func(name string, declared, actual bool, severity skil.Severity, rules ...string) {
		if actual && !declared {
			result.Mismatches = append(result.Mismatches, Mismatch{
				Capability: name, Kind: "underdeclared", Declared: false, Observed: true, Severity: severity, Evidence: matching(findings, rules...),
			})
		}
	}
	c := contract.Capabilities
	check("network.outbound", c.Network.Outbound, observed.NetworkOutbound, skil.SeverityCritical, "SKIL-NET-001", "SKIL-SH-001", "SKIL-TAINT-NETWORK")
	check("commands.execute", c.Commands.Execute, observed.CommandsExecute, skil.SeverityCritical, "SKIL-PY-001", "SKIL-PY-002", "SKIL-SH-", "SKIL-JS-001", "SKIL-TAINT-EXECUTION")
	check("filesystem.write", len(c.Filesystem.Write) > 0, observed.FilesystemWrite, skil.SeverityHigh, "SKIL-FS-001", "SKIL-TAINT-FILESYSTEM")
	check("filesystem.delete", len(c.Filesystem.Delete) > 0, observed.FilesystemDelete, skil.SeverityCritical, "SKIL-SH-003")
	check("secrets.read", len(c.Secrets.Read) > 0, observed.SecretsRead, skil.SeverityCritical, "SKIL-SEC-001")
	check("persistence", c.Persistence, observed.Persistence, skil.SeverityHigh, "SKIL-PERSISTENCE-STARTUP")
	check("external_side_effects", c.Agent.ExternalSideEffects, observed.ExternalSideEffects, skil.SeverityHigh, "SKIL-EX-", "SKIL-TAINT-NETWORK")
	checkValues := func(name string, observedValues, allowedValues []string, matcher func(string, []string) bool) {
		for _, value := range observedValues {
			if !matcher(value, allowedValues) {
				result.Mismatches = append(result.Mismatches, Mismatch{
					Capability: name + ":" + value, Kind: "outside-allowlist", Declared: allowedValues,
					Observed: true, Severity: skil.SeverityCritical, Evidence: []string{value},
				})
			}
		}
	}
	checkValues("network.hosts", observed.NetworkHosts, c.Network.Hosts, matchHost)
	checkValues("commands.allow", observed.Commands, c.Commands.Allow, matchCommand)
	checkValues("filesystem.write", observed.FilesystemPaths, c.Filesystem.Write, matchPath)
	checkValues("secrets.read", observed.Secrets, c.Secrets.Read, matchExact)
	checkValues("tools.allow", observed.Tools, c.Tools.Allow, matchExact)
	checkValues("mcp.tools", observed.MCPTools, c.MCP.Tools, matchExact)

	overdeclared := func(name string, declared, actual bool) {
		if declared && !actual {
			result.Mismatches = append(result.Mismatches, Mismatch{
				Capability: name, Kind: "overdeclared", Declared: true, Observed: false,
				Severity: skil.SeverityLow, Evidence: []string{"no static evidence observed"},
			})
		}
	}
	overdeclared("network.outbound", c.Network.Outbound, observed.NetworkOutbound)
	overdeclared("commands.execute", c.Commands.Execute, observed.CommandsExecute)
	overdeclared("filesystem.write", len(c.Filesystem.Write) > 0, observed.FilesystemWrite)
	overdeclared("filesystem.delete", len(c.Filesystem.Delete) > 0, observed.FilesystemDelete)
	overdeclared("secrets.read", len(c.Secrets.Read) > 0, observed.SecretsRead)
	overdeclared("persistence", c.Persistence, observed.Persistence)
	overdeclared("external_side_effects", c.Agent.ExternalSideEffects, observed.ExternalSideEffects)
	overdeclared("filesystem.read", len(c.Filesystem.Read) > 0, observed.FilesystemRead)
	overdeclared("environment.read", len(c.Environment.Read) > 0, observed.EnvironmentRead)

	for _, mismatch := range result.Mismatches {
		if mismatch.Kind == "underdeclared" || mismatch.Kind == "outside-allowlist" {
			result.Status = skil.StatusFail
			break
		}
		if result.Status == skil.StatusPass {
			result.Status = skil.StatusWarn
		}
	}
	if result.Status == skil.StatusFail {
		result.Status = skil.StatusFail
	}
	return result
}

// Infer derives observed capability usage from two independent sources:
// direct CapabilityObservations (an analyzer explicitly reporting that a
// capability was used, whether or not that use was unsafe) and, as a
// fallback for analyzers not yet migrated to emit observations, the
// Findings a scan produced. A capability observed by either source counts
// as observed — Findings can only ever add observations here, never
// subtract one an ObservationAnalyzer already reported.
func Infer(findings []skil.Finding, observations []skil.CapabilityObservation) skil.ObservedCapabilities {
	var o skil.ObservedCapabilities
	for _, obs := range observations {
		switch obs.Capability {
		case "network.outbound", "permission.network", "hook.call.http":
			o.NetworkOutbound = true
		case "commands.execute", "permission.shell", "hook.execute.command":
			o.CommandsExecute = true
		case "filesystem.write", "permission.filesystem.write":
			o.FilesystemWrite = true
		case "filesystem.delete":
			o.FilesystemDelete = true
		case "secrets.read":
			o.SecretsRead = true
		case "persistence":
			o.Persistence = true
		case "external.side_effect":
			o.ExternalSideEffects = true
		case "filesystem.read", "permission.filesystem.read":
			o.FilesystemRead = true
		case "environment.read":
			o.EnvironmentRead = true
		}
		switch obs.Capability {
		case "network.outbound":
			appendEvidenceValue(&o.NetworkHosts, obs.Value)
		case "permission.network":
			appendEvidenceValue(&o.NetworkHosts, strings.TrimPrefix(obs.Value, "domain:"))
		case "hook.call.http":
			appendEvidenceValue(&o.NetworkHosts, observationHost(obs.Value))
		case "commands.execute", "permission.shell", "hook.execute.command":
			appendEvidenceValue(&o.Commands, obs.Value)
		case "filesystem.write", "filesystem.read", "permission.filesystem.write", "permission.filesystem.read":
			appendEvidenceValue(&o.FilesystemPaths, obs.Value)
		case "secrets.read":
			appendEvidenceValue(&o.Secrets, obs.Value)
		case "environment.read":
			appendEvidenceValue(&o.Environment, obs.Value)
		case "permission.tools":
			appendEvidenceValue(&o.Tools, obs.Value)
		case "hook.call.mcp":
			appendEvidenceValue(&o.MCPTools, obs.Value)
		}
	}
	for _, f := range findings {
		if f.RuleID == capabilityMismatchRuleID {
			// Verification output must never be fed back into inference: a
			// capability-mismatch finding (e.g. "overdeclared") records the
			// *absence* of observed evidence and would otherwise be
			// misread as proof the capability was in fact observed.
			continue
		}
		if capability, _ := f.Evidence["capability"].(string); capability != "" {
			switch capability {
			case "network.outbound":
				o.NetworkOutbound = true
			case "commands.execute":
				o.CommandsExecute = true
			case "filesystem.write":
				o.FilesystemWrite = true
			case "filesystem.delete":
				o.FilesystemDelete = true
			case "secrets.read":
				o.SecretsRead = true
			case "persistence":
				o.Persistence = true
			case "external.side_effect":
				o.ExternalSideEffects = true
			}
		}
		switch {
		case f.RuleID == "SKIL-NET-001" || f.RuleID == "SKIL-SH-001" || strings.Contains(f.RuleID, "TAINT-NETWORK"):
			o.NetworkOutbound = true
		case f.RuleID == "SKIL-FS-001" || strings.Contains(f.RuleID, "TAINT-FILESYSTEM"):
			o.FilesystemWrite = true
		case f.RuleID == "SKIL-SH-003":
			o.FilesystemDelete = true
		case f.RuleID == "SKIL-PY-001" || f.RuleID == "SKIL-PY-002" || strings.HasPrefix(f.RuleID, "SKIL-SH-") ||
			f.RuleID == "SKIL-JS-001" || strings.Contains(f.RuleID, "TAINT-EXECUTION"):
			o.CommandsExecute = true
		case f.RuleID == "SKIL-SEC-001":
			o.SecretsRead = true
		case f.RuleID == "SKIL-PERSISTENCE-STARTUP":
			o.Persistence = true
		}
		if strings.HasPrefix(f.RuleID, "SKIL-EX-") || strings.Contains(f.RuleID, "TAINT-NETWORK") {
			o.ExternalSideEffects = true
		}
		appendEvidenceString(&o.NetworkHosts, f.Evidence, "network_host")
		appendEvidenceString(&o.Commands, f.Evidence, "command")
		appendEvidenceString(&o.FilesystemPaths, f.Evidence, "filesystem_path")
		appendEvidenceString(&o.Secrets, f.Evidence, "secret")
		appendEvidenceString(&o.Environment, f.Evidence, "environment")
		appendEvidenceString(&o.Tools, f.Evidence, "tool")
		appendEvidenceString(&o.MCPServers, f.Evidence, "mcp_server")
		appendEvidenceString(&o.MCPTools, f.Evidence, "mcp_tool")
	}
	sort.Strings(o.NetworkHosts)
	sort.Strings(o.Commands)
	sort.Strings(o.FilesystemPaths)
	sort.Strings(o.Secrets)
	return o
}

func observationHost(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return value
	}
	return parsed.Hostname()
}

func appendEvidenceString(target *[]string, evidence map[string]any, key string) {
	value, ok := evidence[key].(string)
	if !ok {
		return
	}
	appendEvidenceValue(target, value)
}

func appendEvidenceValue(target *[]string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	for _, existing := range *target {
		if existing == value {
			return
		}
	}
	*target = append(*target, value)
}

func matchExact(value string, allowed []string) bool {
	for _, item := range allowed {
		if value == item {
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

func matchCommand(value string, allowed []string) bool {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return false
	}
	for _, item := range allowed {
		allowedFields := strings.Fields(item)
		if len(allowedFields) > 0 && fields[0] == allowedFields[0] &&
			(len(allowedFields) == 1 || strings.HasPrefix(value, item)) {
			return true
		}
	}
	return false
}

func matchPath(value string, allowed []string) bool {
	value = filepath.ToSlash(filepath.Clean(value))
	for _, pattern := range allowed {
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

func Findings(result Result, artifact skil.Artifact) []skil.Finding {
	out := make([]skil.Finding, 0, len(result.Mismatches))
	for _, mismatch := range result.Mismatches {
		fp := stable(mismatch.Capability, artifact.Digest)
		out = append(out, skil.Finding{
			ID: "F-" + strings.ToUpper(fp[:12]), RuleID: capabilityMismatchRuleID, Category: "contract-conformance",
			Severity: mismatch.Severity, Confidence: 1, Title: "Capability contract mismatch",
			Message:     fmt.Sprintf("Capability %s has a %s contract mismatch.", mismatch.Capability, mismatch.Kind),
			Evidence:    map[string]any{"capability": mismatch.Capability, "source_findings": mismatch.Evidence},
			Remediation: "Remove the behavior or explicitly declare and constrain the capability.", Fingerprint: fp,
		})
	}
	return out
}

func matching(findings []skil.Finding, prefixes ...string) []string {
	var ids []string
	for _, f := range findings {
		for _, prefix := range prefixes {
			if strings.HasPrefix(f.RuleID, prefix) {
				ids = append(ids, f.ID)
				break
			}
		}
	}
	sort.Strings(ids)
	return ids
}
