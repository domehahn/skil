package analyzer

import "github.com/domehahn/skil/pkg/skil"

// SkillSpectorRules mirrors the publicly documented 64-pattern taxonomy. The
// native analyzers implement these controls through pattern, AST, taint,
// dependency/OSV, YARA, MCP, Unicode, contract, and optional semantic passes.
func SkillSpectorRules() []skil.Rule {
	type spec struct {
		id, title, category, analysis string
		severity                      skil.Severity
	}
	specs := []spec{
		{"P1", "Instruction Override", "prompt-injection", "pattern", skil.SeverityHigh},
		{"P2", "Hidden Instructions", "prompt-injection", "pattern", skil.SeverityHigh},
		{"P3", "Exfiltration Commands", "prompt-injection", "pattern", skil.SeverityHigh},
		{"P4", "Behavior Manipulation", "prompt-injection", "semantic", skil.SeverityMedium},
		{"P5", "Harmful Content", "prompt-injection", "semantic", skil.SeverityCritical},
		{"E1", "External Transmission", "data-exfiltration", "pattern", skil.SeverityMedium},
		{"E2", "Environment Variable Harvesting", "data-exfiltration", "ast", skil.SeverityHigh},
		{"E3", "File System Enumeration", "data-exfiltration", "pattern", skil.SeverityMedium},
		{"E4", "Context Leakage", "data-exfiltration", "taint", skil.SeverityHigh},
		{"PE1", "Excessive Permissions", "privilege-escalation", "verification", skil.SeverityLow},
		{"PE2", "Sudo or Root Execution", "privilege-escalation", "static-code", skil.SeverityMedium},
		{"PE3", "Credential Access", "privilege-escalation", "ast", skil.SeverityHigh},
		{"SC1", "Unpinned Dependencies", "supply-chain", "dependency", skil.SeverityLow},
		{"SC2", "External Script Fetching", "supply-chain", "static-code", skil.SeverityHigh},
		{"SC3", "Obfuscated Code", "supply-chain", "pattern", skil.SeverityHigh},
		{"SC4", "Known Vulnerable Dependencies", "supply-chain", "vulnerability", skil.SeverityHigh},
		{"SC5", "Abandoned Dependencies", "supply-chain", "dependency", skil.SeverityMedium},
		{"SC6", "Typosquatting", "supply-chain", "dependency", skil.SeverityHigh},
		{"EA1", "Unrestricted Tool Access", "excessive-agency", "verification", skil.SeverityHigh},
		{"EA2", "Autonomous Decision Making", "excessive-agency", "pattern", skil.SeverityHigh},
		{"EA3", "Scope Creep", "excessive-agency", "semantic", skil.SeverityMedium},
		{"EA4", "Unbounded Resource Access", "excessive-agency", "verification", skil.SeverityMedium},
		{"OH1", "Unvalidated Output Injection", "output-handling", "taint", skil.SeverityHigh},
		{"OH2", "Cross-Context Output", "output-handling", "taint", skil.SeverityMedium},
		{"OH3", "Unbounded Output", "output-handling", "verification", skil.SeverityMedium},
		{"P6", "Direct System Prompt Leakage", "system-prompt-leakage", "pattern", skil.SeverityHigh},
		{"P7", "Indirect System Prompt Extraction", "system-prompt-leakage", "pattern", skil.SeverityMedium},
		{"P8", "Tool-Based System Prompt Exfiltration", "system-prompt-leakage", "taint", skil.SeverityHigh},
		{"MP1", "Persistent Context Injection", "memory-poisoning", "pattern", skil.SeverityHigh},
		{"MP2", "Context Window Stuffing", "memory-poisoning", "pattern", skil.SeverityMedium},
		{"MP3", "Memory Manipulation", "memory-poisoning", "pattern", skil.SeverityHigh},
		{"TM1", "Tool Parameter Abuse", "tool-misuse", "ast", skil.SeverityHigh},
		{"TM2", "Tool Chaining Abuse", "tool-misuse", "taint", skil.SeverityHigh},
		{"TM3", "Unsafe Defaults", "tool-misuse", "static-code", skil.SeverityMedium},
		{"RA1", "Self-Modification", "rogue-agent", "pattern", skil.SeverityCritical},
		{"RA2", "Session Persistence", "rogue-agent", "static-code", skil.SeverityHigh},
		{"TR1", "Overly Broad Trigger", "trigger-abuse", "pattern", skil.SeverityMedium},
		{"TR2", "Shadow Command Trigger", "trigger-abuse", "pattern", skil.SeverityHigh},
		{"TR3", "Keyword Baiting Trigger", "trigger-abuse", "pattern", skil.SeverityMedium},
		{"AST1", "exec Call", "dangerous-code", "ast", skil.SeverityCritical},
		{"AST2", "eval Call", "dangerous-code", "ast", skil.SeverityHigh},
		{"AST3", "Dynamic Import", "dangerous-code", "ast", skil.SeverityHigh},
		{"AST4", "subprocess Call", "dangerous-code", "ast", skil.SeverityHigh},
		{"AST5", "os.system or exec-family", "dangerous-code", "ast", skil.SeverityHigh},
		{"AST6", "compile Call", "dangerous-code", "ast", skil.SeverityMedium},
		{"AST7", "Dynamic getattr", "dangerous-code", "ast", skil.SeverityMedium},
		{"AST8", "Dangerous Execution Chain", "dangerous-code", "taint", skil.SeverityCritical},
		{"TT1", "Direct Taint Flow", "taint-tracking", "taint", skil.SeverityHigh},
		{"TT2", "Variable-Mediated Taint Flow", "taint-tracking", "taint", skil.SeverityMedium},
		{"TT3", "Credential Exfiltration Chain", "taint-tracking", "taint", skil.SeverityCritical},
		{"TT4", "File Read to Network Exfiltration", "taint-tracking", "taint", skil.SeverityHigh},
		{"TT5", "External Input to Code Execution", "taint-tracking", "taint", skil.SeverityCritical},
		{"YR1", "Malware Match", "yara-signatures", "yara", skil.SeverityCritical},
		{"YR2", "Webshell Match", "yara-signatures", "yara", skil.SeverityCritical},
		{"YR3", "Cryptominer Match", "yara-signatures", "yara", skil.SeverityHigh},
		{"YR4", "Hack Tool or Exploit Match", "yara-signatures", "yara", skil.SeverityHigh},
		{"LP1", "Underdeclared Capability", "mcp-least-privilege", "verification", skil.SeverityHigh},
		{"LP2", "Wildcard Permission", "mcp-least-privilege", "mcp", skil.SeverityMedium},
		{"LP3", "Missing Permission Declaration", "mcp-least-privilege", "verification", skil.SeverityMedium},
		{"LP4", "Overdeclared Permission", "mcp-least-privilege", "verification", skil.SeverityLow},
		{"TP1", "Hidden Instructions in Tool Metadata", "mcp-tool-poisoning", "mcp", skil.SeverityHigh},
		{"TP2", "Unicode Deception", "mcp-tool-poisoning", "pattern", skil.SeverityHigh},
		{"TP3", "Parameter Description Injection", "mcp-tool-poisoning", "mcp", skil.SeverityMedium},
		{"TP4", "Description-Behavior Mismatch", "mcp-tool-poisoning", "semantic", skil.SeverityMedium},
	}
	out := make([]skil.Rule, 0, len(specs))
	for _, item := range specs {
		out = append(out, skil.Rule{ID: "SKILLSPECTOR-" + item.id, Title: item.title, Category: item.category,
			Severity: item.severity, Description: "Compatibility control for " + item.title + ".",
			Analysis: item.analysis, Remediation: "Review the evidence and remove or explicitly constrain the behavior."})
	}
	return out
}
