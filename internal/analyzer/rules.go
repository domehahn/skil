package analyzer

import (
	"sort"

	"github.com/domehahn/skil/pkg/skil"
)

// BuiltinRules returns the stable public catalog. Rules emitted from provider
// vulnerability IDs retain SKIL-DEP-VULN and include the upstream ID as a
// reference rather than creating unstable rule identifiers.
func BuiltinRules() []skil.Rule {
	out := NewPattern().Rules()
	out = append(out, NewCode().Rules()...)
	out = append(out, NewPythonAST().Rules()...)
	out = append(out, NewStructuredAST().Rules()...)
	out = append(out, nativeSupplementalRules()...)
	byID := make(map[string]skil.Rule, len(out))
	for _, rule := range out {
		if _, exists := byID[rule.ID]; !exists {
			byID[rule.ID] = rule
		}
	}
	out = out[:0]
	for _, rule := range byID {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func nativeSupplementalRules() []skil.Rule {
	return []skil.Rule{
		{ID: "SKIL-TAINT-NETWORK", Title: "Tainted data reaches network", Category: "data-flow", Severity: skil.SeverityCritical, Analysis: "taint", Description: "Sensitive or untrusted data reaches an outbound network sink.", Remediation: "Validate and constrain the flow before the sink."},
		{ID: "SKIL-TAINT-EXECUTION", Title: "Tainted data reaches execution", Category: "data-flow", Severity: skil.SeverityCritical, Analysis: "taint", Description: "Untrusted data reaches a dynamic execution sink.", Remediation: "Remove dynamic execution or use an explicit allowlist."},
		{ID: "SKIL-TAINT-FILESYSTEM-WRITE", Title: "Tainted data reaches filesystem write", Category: "data-flow", Severity: skil.SeverityHigh, Analysis: "taint", Description: "Untrusted data reaches a filesystem write.", Remediation: "Validate paths and content before writing."},
		{ID: "SKIL-TAINT-LOG", Title: "Tainted data reaches logs", Category: "data-flow", Severity: skil.SeverityMedium, Analysis: "taint", Description: "Potentially sensitive data reaches logging.", Remediation: "Redact secrets and constrain logged content."},
		{ID: "SKIL-DEP-001", Title: "Unpinned dependency", Category: "dependency-trust", Severity: skil.SeverityMedium, Analysis: "dependency", Description: "A dependency is not pinned to an exact version.", Remediation: "Pin and integrity-check the dependency."},
		{ID: "SKIL-DEP-002", Title: "Suspicious dependency name", Category: "dependency-trust", Severity: skil.SeverityHigh, Analysis: "dependency", Description: "A dependency resembles a deceptive package identity.", Remediation: "Verify the package identity and publisher."},
		{ID: "SKIL-DEP-ABANDONED", Title: "Abandoned dependency", Category: "dependency-trust", Severity: skil.SeverityMedium, Analysis: "dependency", Description: "Package reputation metadata marks the dependency as abandoned.", Remediation: "Replace the package with an actively maintained alternative."},
		{ID: "SKIL-DEP-VULN", Title: "Known vulnerable dependency", Category: "dependency-trust", Severity: skil.SeverityHigh, Analysis: "dependency", Description: "A vulnerability provider reported a known issue.", Remediation: "Upgrade to a patched version."},
		{ID: "SKIL-MCP-001", Title: "Wildcard MCP permission", Category: "tool-protocol", Severity: skil.SeverityHigh, Analysis: "mcp", Description: "MCP configuration grants an unconstrained wildcard.", Remediation: "Declare exact servers and tools."},
		{ID: "SKIL-MCP-002", Title: "MCP metadata instruction injection", Category: "tool-protocol", Severity: skil.SeverityCritical, Analysis: "mcp", Description: "A tool description embeds manipulative instructions.", Remediation: "Remove instructions and bind descriptions to reviewed behavior."},
		{ID: "SKIL-UNI-001", Title: "Unicode deception control", Category: "artifact-integrity", Severity: skil.SeverityHigh, Analysis: "pattern", Description: "Text contains invisible or bidirectional control characters.", Remediation: "Remove or explicitly justify the controls."},
		{ID: "SKIL-OBF-001", Title: "Encoded security-sensitive instruction", Category: "instruction-integrity", Severity: skil.SeverityHigh, Analysis: "pattern", Description: "Encoded content contains security-sensitive instructions.", Remediation: "Use reviewable plaintext and remove malicious instructions."},
		{ID: "SKIL-INTENT-DESCRIPTION", Title: "Description and behavior conflict", Category: "intent-integrity", Severity: skil.SeverityMedium, Analysis: "semantic", Description: "Observed behavior conflicts with the stated purpose.", Remediation: "Align the implementation and the reviewed description."},
		{ID: "SKIL-INTENT-CONTEXT", Title: "Context-inappropriate capability", Category: "intent-integrity", Severity: skil.SeverityMedium, Analysis: "semantic", Description: "A capability is inappropriate for the declared operating context.", Remediation: "Remove the capability or constrain the operating context."},
		{ID: "SKIL-INTENT-SCOPE", Title: "Capability scope expansion", Category: "intent-integrity", Severity: skil.SeverityHigh, Analysis: "semantic", Description: "Behavior extends beyond the declared capability boundary.", Remediation: "Remove the behavior or explicitly narrow and approve the contract."},
		{ID: "SKIL-INTENT-IMPLEMENTATION", Title: "Intent and implementation divergence", Category: "intent-integrity", Severity: skil.SeverityHigh, Analysis: "semantic", Description: "Implementation contradicts an explicit behavioral statement.", Remediation: "Make the implementation conform to the reviewed intent."},
		{ID: "SKIL-YARA-*", Title: "YARA malware signature", Category: "malware", Severity: skil.SeverityCritical, Analysis: "yara", Description: "A trusted YARA source rule matched artifact content.", Remediation: "Quarantine and investigate the artifact."},
		{ID: "SKIL-CAP-001", Title: "Undeclared capability", Category: "contract-conformance", Severity: skil.SeverityHigh, Analysis: "verification", Description: "Observed behavior is outside the declared contract.", Remediation: "Remove or explicitly constrain the capability."},
	}
}

type ControlImplementation struct {
	Engine         string
	ProviderBacked bool
}

// NativeControlImplementations is the auditable link between every public
// control and the code path that can emit it.
func NativeControlImplementations() map[string]ControlImplementation {
	out := map[string]ControlImplementation{}
	for _, rule := range NewPattern().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.pattern"}
	}
	for _, rule := range NewCode().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.structured-ast"}
	}
	for _, rule := range NewPythonAST().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.python-ast"}
	}
	for _, rule := range NewStructuredAST().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.structured-ast"}
	}
	for _, id := range []string{"SKIL-PY-001", "SKIL-PY-002", "SKIL-PY-003", "SKIL-PY-004"} {
		out[id] = ControlImplementation{Engine: "builtin.python-ast"}
	}
	engines := map[string]ControlImplementation{
		"SKIL-TAINT-NETWORK":          {Engine: "builtin.taint"},
		"SKIL-TAINT-EXECUTION":        {Engine: "builtin.taint"},
		"SKIL-TAINT-FILESYSTEM-WRITE": {Engine: "builtin.taint"},
		"SKIL-TAINT-LOG":              {Engine: "builtin.taint"},
		"SKIL-DEP-001":                {Engine: "builtin.dependency"},
		"SKIL-DEP-002":                {Engine: "builtin.dependency"},
		"SKIL-DEP-ABANDONED":          {Engine: "reputation-provider", ProviderBacked: true},
		"SKIL-DEP-VULN":               {Engine: "vulnerability-provider", ProviderBacked: true},
		"SKIL-MCP-001":                {Engine: "builtin.mcp"},
		"SKIL-MCP-002":                {Engine: "builtin.mcp"},
		"SKIL-UNI-001":                {Engine: "builtin.unicode"},
		"SKIL-OBF-001":                {Engine: "builtin.unicode"},
		"SKIL-INTENT-DESCRIPTION":     {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-INTENT-CONTEXT":         {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-INTENT-SCOPE":           {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-INTENT-IMPLEMENTATION":  {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-YARA-*":                 {Engine: "yara-provider", ProviderBacked: true},
		"SKIL-CAP-001":                {Engine: "contract-verification"},
	}
	for id, implementation := range engines {
		out[id] = implementation
	}
	return out
}
