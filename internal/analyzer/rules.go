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
	out = append(out, NewBoundary().Rules()...)
	out = append(out, NewModelArtifact().Rules()...)
	out = append(out, NewSecret().Rules()...)
	out = append(out, NewBuild().Rules()...)
	out = append(out, NewIdentity().Rules()...)
	out = append(out, NewLateral().Rules()...)
	out = append(out, NewAsset().Rules()...)
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
		{ID: "SKIL-DEP-MALICIOUS", Title: "Malicious dependency", Category: "dependency-trust", Severity: skil.SeverityCritical, Analysis: "dependency", Description: "A malicious-package advisory reports the dependency itself is hostile, not merely vulnerable.", Remediation: "Remove the package entirely; do not merely upgrade it."},
		{ID: "SKIL-CONTAINER-TRUST", Title: "Disabled container trust", Category: "supply-chain-integrity", Severity: skil.SeverityHigh, Analysis: "ast", Description: "Container content trust or registry verification is disabled.", Remediation: "Use immutable image digests and verified signatures."},
		{ID: "SKIL-MCP-001", Title: "Wildcard MCP permission", Category: "tool-protocol", Severity: skil.SeverityHigh, Analysis: "mcp", Description: "MCP configuration grants an unconstrained wildcard.", Remediation: "Declare exact servers and tools."},
		{ID: "SKIL-MCP-002", Title: "MCP metadata instruction injection", Category: "tool-protocol", Severity: skil.SeverityCritical, Analysis: "mcp", Description: "A tool description embeds manipulative instructions.", Remediation: "Remove instructions and bind descriptions to reviewed behavior."},
		{ID: "SKIL-MCP-003", Title: "Mutable MCP tool identity", Category: "tool-protocol", Severity: skil.SeverityHigh, Analysis: "mcp", Description: "An MCP server or tool is resolved from a mutable package or revision.", Remediation: "Pin an immutable version and verify its digest."},
		{ID: "SKIL-MCP-004", Title: "MCP parameter description injection", Category: "tool-protocol", Severity: skil.SeverityCritical, Analysis: "mcp", Description: "An MCP parameter description requests secrets or credentials.", Remediation: "Remove credential-collection instructions from parameter metadata."},
		{ID: "SKIL-MCP-005", Title: "MCP tool metadata rug pull", Category: "tool-protocol", Severity: skil.SeverityCritical, Analysis: "mcp", Description: "MCP metadata differs from its reviewed immutable lock.", Remediation: "Re-review metadata before updating the lock."},
		{ID: "SKIL-MCP-006", Title: "MCP description and behavior mismatch", Category: "tool-protocol", Severity: skil.SeverityHigh, Analysis: "mcp", Description: "MCP implementation behavior exceeds its reviewed description.", Remediation: "Align behavior and description."},
		{ID: "SKIL-MCP-007", Title: "Excessive MCP parameter description length", Category: "tool-protocol", Severity: skil.SeverityMedium, Analysis: "mcp", Description: "A parameter description is unusually long, which can conceal an embedded instruction payload.", Remediation: "Keep parameter descriptions short and limited to describing the parameter's value."},
		{ID: "SKIL-UNI-001", Title: "Unicode deception control", Category: "artifact-integrity", Severity: skil.SeverityHigh, Analysis: "pattern", Description: "Text contains invisible or bidirectional control characters.", Remediation: "Remove or explicitly justify the controls."},
		{ID: "SKIL-OBF-001", Title: "Encoded security-sensitive instruction", Category: "instruction-integrity", Severity: skil.SeverityHigh, Analysis: "pattern", Description: "Encoded content contains security-sensitive instructions.", Remediation: "Use reviewable plaintext and remove malicious instructions."},
		{ID: "SKIL-INTENT-DESCRIPTION", Title: "Description and behavior conflict", Category: "intent-integrity", Severity: skil.SeverityMedium, Analysis: "semantic", Description: "Observed behavior conflicts with the stated purpose.", Remediation: "Align the implementation and the reviewed description."},
		{ID: "SKIL-INTENT-CONTEXT", Title: "Context-inappropriate capability", Category: "intent-integrity", Severity: skil.SeverityMedium, Analysis: "semantic", Description: "A capability is inappropriate for the declared operating context.", Remediation: "Remove the capability or constrain the operating context."},
		{ID: "SKIL-INTENT-SCOPE", Title: "Capability scope expansion", Category: "intent-integrity", Severity: skil.SeverityHigh, Analysis: "semantic", Description: "Behavior extends beyond the declared capability boundary.", Remediation: "Remove the behavior or explicitly narrow and approve the contract."},
		{ID: "SKIL-INTENT-IMPLEMENTATION", Title: "Intent and implementation divergence", Category: "intent-integrity", Severity: skil.SeverityHigh, Analysis: "semantic", Description: "Implementation contradicts an explicit behavioral statement.", Remediation: "Make the implementation conform to the reviewed intent."},
		{ID: "SKIL-SEM-SECURITY", Title: "Semantic security weakness", Category: "semantic-security", Severity: skil.SeverityHigh, Analysis: "semantic", Description: "Contextual analysis identified a security weakness not reducible to a lexical pattern.", Remediation: "Constrain the behavior and add an enforceable security control."},
		{ID: "SKIL-SEM-QUALITY", Title: "Semantic quality defect", Category: "quality-policy", Severity: skil.SeverityMedium, Analysis: "semantic", Description: "Contextual analysis identified ambiguity, contradiction, or a missing precondition.", Remediation: "Clarify the contract and make behavior deterministic and testable."},
		{ID: "SKIL-SEM-COMPOSITE", Title: "Composite semantic risk", Category: "semantic-composition", Severity: skil.SeverityHigh, Analysis: "semantic", Description: "Independent semantic observations combine into a material cross-boundary risk.", Remediation: "Resolve the contributing observations and verify the combined behavior."},
		{ID: "SKIL-SEM-POLICY", Title: "Organization-policy violation", Category: "quality-policy", Severity: skil.SeverityMedium, Analysis: "semantic", Description: "Contextual analysis identified behavior that conflicts with an organization's content or operational policy (e.g. forced language, prohibited subject matter).", Remediation: "Conform the skill to the organization's reviewed policy or exclude it from deployment."},
		{ID: "SKIL-YARA-*", Title: "Malware signature", Category: "malware", Severity: skil.SeverityCritical, Analysis: "yara", Description: "A native or trusted external malware signature matched artifact content.", Remediation: "Quarantine and investigate the artifact."},
		{ID: "SKIL-UNI-002", Title: "Unicode hostname confusable", Category: "artifact-integrity", Severity: skil.SeverityHigh, Analysis: "pattern", Description: "A hostname-like token mixes Latin and Cyrillic characters.", Remediation: "Use an ASCII or IDNA-normalized reviewed hostname."},
		{ID: "SKIL-UNI-003", Title: "Unicode tag instruction smuggling", Category: "instruction-integrity", Severity: skil.SeverityHigh, Analysis: "pattern", Description: "Unicode tag characters conceal a security-sensitive instruction.", Remediation: "Remove tag characters and keep instructions visible."},
		{ID: "SKIL-CAP-001", Title: "Undeclared capability", Category: "contract-conformance", Severity: skil.SeverityHigh, Analysis: "verification", Description: "Observed behavior is outside the declared contract.", Remediation: "Remove or explicitly constrain the capability."},
		{ID: "SKIL-CAP-DECLARATION-MISSING", Title: "Capability declaration missing", Category: "contract-conformance", Severity: skil.SeverityMedium, Analysis: "verification", Description: "Security-sensitive behavior exists without a skill contract.", Remediation: "Add a narrowly scoped skill contract."},
		{ID: "SKIL-TAINT-PRIVILEGED-CONTEXT", Title: "Privileged context reaches external sink", Category: "data-flow", Severity: skil.SeverityCritical, Analysis: "taint", Description: "System prompt, developer instructions, or privileged context flows to a network, file, tool, or log sink.", Remediation: "Constrain privileged context to local processing only."},
		{ID: "SKIL-TAINT-OUTPUT-EXECUTION", Title: "LLM output reaches execution sink", Category: "data-flow", Severity: skil.SeverityCritical, Analysis: "taint", Description: "Model or tool output flows to an exec, eval, shell, SQL, or HTML-rendering sink without validation.", Remediation: "Validate and encode LLM output before any execution or rendering sink."},
		{ID: "SKIL-TAINT-OUTPUT-CROSS-AGENT", Title: "LLM output reaches another agent", Category: "multi-agent", Severity: skil.SeverityHigh, Analysis: "taint", Description: "Model or tool output is forwarded to another agent without validation or trust boundary enforcement.", Remediation: "Validate, label, and constrain cross-agent output to prevent injection."},
		{ID: "SKIL-PI-HIDDEN-COMMENT", Title: "Hidden instruction in render-suppressed region", Category: "instruction-integrity", Severity: skil.SeverityCritical, Analysis: "pattern", Description: "An HTML or Markdown comment contains security-sensitive instructions invisible when rendered.", Remediation: "Remove hidden instructions or make them visible for review."},
		{ID: "SKIL-TRIGGER-LOCK-DIFF", Title: "Trigger surface changed from lock", Category: "activation-integrity", Severity: skil.SeverityHigh, Analysis: "trigger", Description: "The declared trigger set differs from the reviewed baseline or lock.", Remediation: "Re-review triggers and update the lock."},
		{ID: "SKIL-RESOURCE-UNLIMITED", Title: "Unlimited resource allocation", Category: "resource-boundary", Severity: skil.SeverityMedium, Analysis: "resource-config", Description: "A resource limit is set to None, null, or infinity allowing unbounded consumption.", Remediation: "Set finite resource limits aligned with the operational budget."},
		{ID: "SKIL-RESOURCE-TIMEOUT", Title: "Disabled timeout or retry bound", Category: "resource-boundary", Severity: skil.SeverityMedium, Analysis: "resource-config", Description: "A timeout or retry parameter is unset or unbounded risking resource starvation.", Remediation: "Set explicit finite timeouts and retry limits."},
		{ID: "SKIL-RESOURCE-UNBOUNDED-LOOP", Title: "Unbounded loop or recursion risk", Category: "resource-boundary", Severity: skil.SeverityHigh, Analysis: "resource-config", Description: "Code or configuration allows unbounded retries polling or recursion without a termination condition.", Remediation: "Add max-iterations timeout or circuit-breaker to bound the loop."},
		{ID: "SKIL-MEMORY-FALSE-RESET", Title: "Simulated memory reset", Category: "state-integrity", Severity: skil.SeverityHigh, Analysis: "pattern", Description: "Instructions ask the agent to simulate memory loss while retaining execution context enabling false-deniability.", Remediation: "Remove false-memory-reset framing; use explicit audited memory-clear if reset is required."},
		{ID: "SKIL-MEMORY-FALSE-REPRESENTATION", Title: "False identity representation", Category: "state-integrity", Severity: skil.SeverityHigh, Analysis: "pattern", Description: "Instructions direct the agent to falsely represent its identity as a human or different entity.", Remediation: "Remove false-identity representation; disclose AI identity transparently."},
		{ID: "SKIL-PI-SUSPICIOUS-COMMENT", Title: "Render-suppressed region with unusual length", Category: "instruction-integrity", Severity: skil.SeverityMedium, Analysis: "pattern", Description: "An unusually long HTML or Markdown comment may conceal instructions or data.", Remediation: "Review and remove unreasonably large comments."},
		{ID: "SKIL-PI-MD-HIDDEN-COMMENT", Title: "Hidden instruction in Markdown comment reference", Category: "instruction-integrity", Severity: skil.SeverityCritical, Analysis: "pattern", Description: "A Markdown comment reference (`[//]: #(...)`) contains security-sensitive instructions invisible when rendered.", Remediation: "Remove hidden instructions or make them visible for review."},
		{ID: "SKIL-PI-MD-SUSPICIOUS-COMMENT", Title: "Markdown comment reference with unusual length", Category: "instruction-integrity", Severity: skil.SeverityMedium, Analysis: "pattern", Description: "An unusually long Markdown comment reference may conceal instructions or data.", Remediation: "Review and remove unreasonably large comments."},
		{ID: "SKIL-TRIGGER-BAITING", Title: "Keyword baiting trigger", Category: "activation-integrity", Severity: skil.SeverityMedium, Analysis: "trigger", Description: "A trigger uses a common code or data keyword increasing unintentional activation risk.", Remediation: "Use a narrow, domain-specific trigger phrase."},
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
	for _, rule := range NewBoundary().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.boundary"}
	}
	for _, rule := range NewModelArtifact().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.model-artifact"}
	}
	for _, rule := range NewSecret().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.secret"}
	}
	for _, rule := range NewBuild().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.build"}
	}
	for _, rule := range NewIdentity().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.identity"}
	}
	for _, rule := range NewLateral().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.lateral"}
	}
	for _, rule := range NewAsset().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.asset"}
	}
	for _, rule := range NewHiddenInstruction().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.hidden-instruction"}
	}
	for _, rule := range NewTrigger().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.trigger"}
	}
	for _, rule := range NewResourceConfig().Rules() {
		out[rule.ID] = ControlImplementation{Engine: "builtin.resource-config"}
	}
	for _, id := range []string{"SKIL-PY-001", "SKIL-PY-002", "SKIL-PY-003", "SKIL-PY-004"} {
		out[id] = ControlImplementation{Engine: "builtin.python-ast"}
	}
	engines := map[string]ControlImplementation{
		"SKIL-TAINT-NETWORK":               {Engine: "builtin.taint"},
		"SKIL-TAINT-EXECUTION":             {Engine: "builtin.taint"},
		"SKIL-TAINT-FILESYSTEM-WRITE":      {Engine: "builtin.taint"},
		"SKIL-TAINT-LOG":                   {Engine: "builtin.taint"},
		"SKIL-TAINT-PRIVILEGED-CONTEXT":    {Engine: "builtin.taint"},
		"SKIL-TAINT-OUTPUT-EXECUTION":      {Engine: "builtin.taint"},
		"SKIL-TAINT-OUTPUT-CROSS-AGENT":    {Engine: "builtin.taint"},
		"SKIL-DEP-001":                     {Engine: "builtin.dependency"},
		"SKIL-DEP-002":                     {Engine: "builtin.dependency"},
		"SKIL-DEP-ABANDONED":               {Engine: "reputation-provider", ProviderBacked: true},
		"SKIL-DEP-VULN":                    {Engine: "vulnerability-provider", ProviderBacked: true},
		"SKIL-DEP-MALICIOUS":               {Engine: "vulnerability-provider", ProviderBacked: true},
		"SKIL-CONTAINER-TRUST":             {Engine: "builtin.structured-ast"},
		"SKIL-MCP-001":                     {Engine: "builtin.mcp"},
		"SKIL-MCP-002":                     {Engine: "builtin.mcp"},
		"SKIL-MCP-003":                     {Engine: "builtin.mcp"},
		"SKIL-MCP-004":                     {Engine: "builtin.mcp"},
		"SKIL-MCP-005":                     {Engine: "builtin.mcp"},
		"SKIL-MCP-006":                     {Engine: "builtin.mcp"},
		"SKIL-MCP-007":                     {Engine: "builtin.mcp"},
		"SKIL-UNI-001":                     {Engine: "builtin.unicode"},
		"SKIL-OBF-001":                     {Engine: "builtin.unicode"},
		"SKIL-INTENT-DESCRIPTION":          {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-INTENT-CONTEXT":              {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-INTENT-SCOPE":                {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-INTENT-IMPLEMENTATION":       {Engine: "builtin.local-semantic"},
		"SKIL-SEM-SECURITY":                {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-SEM-QUALITY":                 {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-SEM-COMPOSITE":               {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-SEM-POLICY":                  {Engine: "semantic-provider", ProviderBacked: true},
		"SKIL-YARA-*":                      {Engine: "builtin.native-malware/external-yara"},
		"SKIL-UNI-002":                     {Engine: "builtin.obfuscation"},
		"SKIL-UNI-003":                     {Engine: "builtin.obfuscation"},
		"SKIL-CAP-001":                     {Engine: "contract-verification"},
		"SKIL-CAP-DECLARATION-MISSING":     {Engine: "registry.conformance"},
		"SKIL-MEMORY-FALSE-RESET":          {Engine: "builtin.pattern"},
		"SKIL-MEMORY-FALSE-REPRESENTATION": {Engine: "builtin.pattern"},
	}
	for id, implementation := range engines {
		out[id] = implementation
	}
	return out
}
