package lint

import (
	"sort"

	"github.com/domehahn/skil/pkg/skil"
)

// Rules returns the stable, user-visible authoring rules emitted by Analyze.
func Rules() []skil.Rule {
	definitions := []struct {
		id, title string
		severity  skil.Severity
	}{
		{"SKIL-LINT-ANCHOR-BROKEN", "Broken Markdown anchor", skil.SeverityMedium},
		{"SKIL-LINT-ANCHOR-DUPLICATE", "Duplicate Markdown anchor", skil.SeverityMedium},
		{"SKIL-LINT-BOM", "UTF-8 byte-order mark", skil.SeverityMedium},
		{"SKIL-LINT-CAPABILITY-EMPTY", "Empty capability entry", skil.SeverityHigh},
		{"SKIL-LINT-CAPABILITY-WILDCARD", "Unbounded capability", skil.SeverityMedium},
		{"SKIL-LINT-CHANGELOG-VERSION", "Version absent from changelog", skil.SeverityHigh},
		{"SKIL-LINT-CODE-FENCE", "Unclosed Markdown code fence", skil.SeverityHigh},
		{"SKIL-LINT-CONTRACT-AMBIGUOUS", "Ambiguous skill contract", skil.SeverityHigh},
		{"SKIL-LINT-CONTRACT-INVALID", "Invalid skill contract", skil.SeverityHigh},
		{"SKIL-LINT-CONTRACT-MISSING", "Missing skill contract", skil.SeverityHigh},
		{"SKIL-LINT-DEPENDENCY-RANGE", "Non-deterministic dependency version", skil.SeverityMedium},
		{"SKIL-LINT-DESCRIPTION-MISMATCH", "Skill description mismatch", skil.SeverityMedium},
		{"SKIL-LINT-ENTRYPOINT-MODE", "Script entrypoint is not executable", skil.SeverityMedium},
		{"SKIL-LINT-EVAL-ASSERTIONS", "Evaluation has no assertions", skil.SeverityMedium},
		{"SKIL-LINT-EVAL-ATTACK", "Adversarial evaluation lacks attack metadata", skil.SeverityMedium},
		{"SKIL-LINT-EVAL-NAME-DUPLICATE", "Duplicate evaluation name", skil.SeverityHigh},
		{"SKIL-LINT-EVAL-SCHEMA", "Invalid evaluation specification", skil.SeverityHigh},
		{"SKIL-LINT-EVAL-TOOL", "Evaluation uses undeclared tool", skil.SeverityMedium},
		{"SKIL-LINT-EXTERNAL-CONFIRMATION", "External confirmation disabled", skil.SeverityMedium},
		{"SKIL-LINT-EXTERNAL-TARGETS", "Unbounded external side effects", skil.SeverityMedium},
		{"SKIL-LINT-FILENAME-PORTABILITY", "Non-portable filename", skil.SeverityMedium},
		{"SKIL-LINT-FILESYSTEM-SCOPE", "Unsafe filesystem capability", skil.SeverityHigh},
		{"SKIL-LINT-FRONTMATTER-DESCRIPTION", "Missing frontmatter description", skil.SeverityMedium},
		{"SKIL-LINT-FRONTMATTER-INVALID", "Invalid SKILL.md frontmatter", skil.SeverityHigh},
		{"SKIL-LINT-FRONTMATTER-MISSING", "Missing SKILL.md frontmatter", skil.SeverityMedium},
		{"SKIL-LINT-FRONTMATTER-NAME", "Missing frontmatter name", skil.SeverityMedium},
		{"SKIL-LINT-H1-MISSING", "Missing primary heading", skil.SeverityMedium},
		{"SKIL-LINT-H1-MULTIPLE", "Multiple primary headings", skil.SeverityMedium},
		{"SKIL-LINT-HOST-FORMAT", "Invalid network host", skil.SeverityHigh},
		{"SKIL-LINT-IMPORT-BROKEN", "Unresolved local import", skil.SeverityMedium},
		{"SKIL-LINT-INACTIVE-COMMANDS", "Unused command allowlist", skil.SeverityMedium},
		{"SKIL-LINT-INACTIVE-HOSTS", "Unused network allowlist", skil.SeverityMedium},
		{"SKIL-LINT-JSON", "Invalid JSON", skil.SeverityHigh},
		{"SKIL-LINT-JSON-DUPLICATE-KEY", "Duplicate JSON key", skil.SeverityHigh},
		{"SKIL-LINT-LICENSE-MISSING", "Missing license file", skil.SeverityMedium},
		{"SKIL-LINT-LINE-ENDINGS", "Non-portable line endings", skil.SeverityMedium},
		{"SKIL-LINT-LINK-BROKEN", "Broken local link", skil.SeverityMedium},
		{"SKIL-LINT-LINK-ESCAPE", "Escaping local link", skil.SeverityHigh},
		{"SKIL-LINT-LOCKFILE-CONFLICT", "Competing dependency lockfiles", skil.SeverityMedium},
		{"SKIL-LINT-LOCKFILE-DRIFT", "Dependency manifest and lockfile drift", skil.SeverityMedium},
		{"SKIL-LINT-LOCKFILE-MISSING", "Missing dependency lockfile", skil.SeverityMedium},
		{"SKIL-LINT-LOCKFILE-ORPHAN", "Orphan dependency lockfile", skil.SeverityMedium},
		{"SKIL-LINT-MCP-INPUT-SCHEMA", "Invalid MCP input schema", skil.SeverityHigh},
		{"SKIL-LINT-MCP-LOCK", "Invalid MCP metadata lock", skil.SeverityHigh},
		{"SKIL-LINT-MCP-REFERENCE", "Unknown declared MCP capability", skil.SeverityMedium},
		{"SKIL-LINT-MCP-TOOL-DUPLICATE", "Duplicate MCP tool name", skil.SeverityHigh},
		{"SKIL-LINT-MCP-TOOL-NAME", "Missing MCP tool name", skil.SeverityHigh},
		{"SKIL-LINT-MCP-UNDECLARED", "MCP configuration missing from contract", skil.SeverityMedium},
		{"SKIL-LINT-NAME-MISMATCH", "Skill name mismatch", skil.SeverityMedium},
		{"SKIL-LINT-NAME-STYLE", "Non-portable skill name", skil.SeverityMedium},
		{"SKIL-LINT-OWNER", "Missing owner", skil.SeverityMedium},
		{"SKIL-LINT-PACKAGE", "Invalid authoring package", skil.SeverityHigh},
		{"SKIL-LINT-PLACEHOLDER", "Unresolved authoring placeholder", skil.SeverityMedium},
		{"SKIL-LINT-RESOURCE-BOUNDS", "Excessive resource limit", skil.SeverityMedium},
		{"SKIL-LINT-RESOURCE-LIMITS", "Missing resource limits", skil.SeverityMedium},
		{"SKIL-LINT-SHEBANG-MISMATCH", "Shebang conflicts with file type", skil.SeverityMedium},
		{"SKIL-LINT-SHEBANG-MISSING", "Executable script lacks shebang", skil.SeverityMedium},
		{"SKIL-LINT-SKILL-EMPTY", "Empty SKILL.md", skil.SeverityHigh},
		{"SKIL-LINT-SKILL-MISSING", "Missing SKILL.md", skil.SeverityHigh},
		{"SKIL-LINT-TEMPORARY-FILE", "Temporary or generated artifact", skil.SeverityMedium},
		{"SKIL-LINT-TOOL-CONFLICT", "Conflicting tool policy", skil.SeverityHigh},
		{"SKIL-LINT-TOOL-SHADOWED", "Allowed tool shadowed by deny pattern", skil.SeverityMedium},
		{"SKIL-LINT-UTF8", "Invalid UTF-8", skil.SeverityHigh},
		{"SKIL-LINT-VERSION", "Invalid semantic version", skil.SeverityHigh},
		{"SKIL-LINT-GLOB", "Invalid capability glob", skil.SeverityHigh},
	}
	rules := make([]skil.Rule, 0, len(definitions))
	for _, definition := range definitions {
		rules = append(rules, skil.Rule{
			ID: definition.id, Title: definition.title, Category: "lint",
			Severity: definition.severity, Analysis: "lint",
			Description: "Fast, provider-free skill authoring and consistency check.",
			Remediation: "Correct the authoring issue before running the security scan.",
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}
