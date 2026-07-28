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
	out = append(out, SkillSpectorRules()...)
	extra := []skil.Rule{
		{ID: "SKIL-TAINT-NETWORK", Title: "Tainted data reaches network", Category: "taint-flow", Severity: skil.SeverityCritical, Analysis: "taint", Description: "Sensitive or untrusted data reaches an outbound network sink.", Remediation: "Validate and constrain the flow before the sink."},
		{ID: "SKIL-TAINT-EXECUTION", Title: "Tainted data reaches execution", Category: "taint-flow", Severity: skil.SeverityCritical, Analysis: "taint", Description: "Untrusted data reaches a dynamic execution sink.", Remediation: "Remove dynamic execution or use an explicit allowlist."},
		{ID: "SKIL-TAINT-FILESYSTEM-WRITE", Title: "Tainted data reaches filesystem write", Category: "taint-flow", Severity: skil.SeverityHigh, Analysis: "taint", Description: "Untrusted data reaches a filesystem write.", Remediation: "Validate paths and content before writing."},
		{ID: "SKIL-TAINT-LOG", Title: "Tainted data reaches logs", Category: "taint-flow", Severity: skil.SeverityMedium, Analysis: "taint", Description: "Potentially sensitive data reaches logging.", Remediation: "Redact secrets and constrain logged content."},
		{ID: "SKIL-DEP-001", Title: "Unpinned dependency", Category: "dependency-security", Severity: skil.SeverityMedium, Analysis: "dependency", Description: "A dependency is not pinned to an exact version.", Remediation: "Pin and integrity-check the dependency."},
		{ID: "SKIL-DEP-002", Title: "Suspicious dependency name", Category: "supply-chain", Severity: skil.SeverityHigh, Analysis: "dependency", Description: "A dependency resembles a typosquatting indicator.", Remediation: "Verify the package identity and publisher."},
		{ID: "SKIL-DEP-VULN", Title: "Known vulnerable dependency", Category: "dependency-security", Severity: skil.SeverityHigh, Analysis: "dependency", Description: "A vulnerability provider reported a known issue.", Remediation: "Upgrade to a patched version."},
		{ID: "SKIL-MCP-001", Title: "Wildcard MCP permission", Category: "mcp-least-privilege", Severity: skil.SeverityHigh, Analysis: "mcp", Description: "MCP configuration grants an unconstrained wildcard.", Remediation: "Declare exact servers and tools."},
		{ID: "SKIL-MCP-002", Title: "MCP tool description poisoning", Category: "mcp-tool-poisoning", Severity: skil.SeverityCritical, Analysis: "mcp", Description: "A tool description embeds manipulative instructions.", Remediation: "Remove instructions and bind descriptions to reviewed behavior."},
		{ID: "SKIL-UNI-001", Title: "Unicode deception control", Category: "integrity", Severity: skil.SeverityHigh, Analysis: "pattern", Description: "Text contains invisible or bidirectional control characters.", Remediation: "Remove or explicitly justify the controls."},
		{ID: "SKIL-OBF-001", Title: "Encoded security-sensitive instruction", Category: "prompt-injection", Severity: skil.SeverityHigh, Analysis: "pattern", Description: "Encoded content contains security-sensitive instructions.", Remediation: "Use reviewable plaintext and remove malicious instructions."},
		{ID: "SKIL-SEM-001", Title: "Semantic security observation", Category: "behavioral", Severity: skil.SeverityMedium, Analysis: "semantic", Description: "An explicitly enabled semantic provider identified a probable security concern.", Remediation: "Review the evidence and constrain the skill contract or behavior."},
		{ID: "SKIL-YARA-*", Title: "YARA malware signature", Category: "malware", Severity: skil.SeverityCritical, Analysis: "yara", Description: "A trusted YARA source rule matched artifact content.", Remediation: "Quarantine and investigate the artifact."},
		{ID: "SKIL-CAP-001", Title: "Undeclared capability", Category: "capability-mismatch", Severity: skil.SeverityHigh, Analysis: "verification", Description: "Observed behavior is outside the declared contract.", Remediation: "Remove or explicitly constrain the capability."},
	}
	out = append(out, extra...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
