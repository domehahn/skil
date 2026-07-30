package taxonomy

import (
	"fmt"
	"sort"
	"strings"
)

type DomainID string

const (
	InstructionSecurity       DomainID = "instruction"
	SkillSecurity             DomainID = "skill"
	ToolCapabilitySecurity    DomainID = "tool-capability"
	MCPSecurity               DomainID = "mcp"
	CodeSecurity              DomainID = "code"
	ModelSecurity             DomainID = "model"
	DataDatasetSecurity       DomainID = "data-dataset"
	RAGContextSecurity        DomainID = "rag-context"
	SupplyChainSecurity       DomainID = "supply-chain"
	IdentityAuthorization     DomainID = "identity-auth"
	MultiAgentSecurity        DomainID = "multi-agent"
	RuntimeInfrastructure     DomainID = "runtime-infra"
	NetworkLateralMovement    DomainID = "network-lateral"
	AssetBinaryMalware        DomainID = "asset-malware"
	BehavioralSecurity        DomainID = "behavioral"
	AuditEvidenceSecurity     DomainID = "audit-evidence"
	PolicyEnforcement         DomainID = "policy-enforcement"
)

type Domain struct {
	ID          DomainID       `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Subdomains  []Subdomain    `json:"subdomains"`
	Controls    []Control      `json:"controls"`
}

type Subdomain struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	ControlIDs  []string `json:"control_ids"`
}

type ControlID string

type Control struct {
	ID          ControlID `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Domain      DomainID  `json:"domain"`
	Subdomain   string    `json:"subdomain,omitempty"`
	SKILRule    string    `json:"skil_rule,omitempty"`
	Provider    string    `json:"provider,omitempty"`
}

type Registry struct {
	domains  []Domain
	controls []Control
	byRule   map[string]ControlID
	byDomain map[DomainID][]Control
	byID     map[ControlID]Control
}

func NewRegistry() *Registry {
	r := &Registry{
		domains:  allDomains(),
		controls: allControls(),
		byRule:   map[string]ControlID{},
		byDomain: map[DomainID][]Control{},
		byID:     map[ControlID]Control{},
	}
	for _, c := range r.controls {
		r.byID[c.ID] = c
		if c.SKILRule != "" {
			r.byRule[c.SKILRule] = c.ID
		}
		r.byDomain[c.Domain] = append(r.byDomain[c.Domain], c)
	}
	return r
}

func (r *Registry) Domains() []Domain { return r.domains }

func (r *Registry) Controls() []Control { return r.controls }

func (r *Registry) ControlByID(id ControlID) (Control, bool) {
	c, ok := r.byID[id]
	return c, ok
}

func (r *Registry) ControlByRule(ruleID string) (Control, bool) {
	cid, ok := r.byRule[ruleID]
	if !ok {
		return Control{}, false
	}
	return r.byID[cid], true
}

func (r *Registry) ControlsByDomain(id DomainID) []Control {
	return r.byDomain[id]
}

func (r *Registry) ResolveSKILRule(ruleID string) (Domain, Control, error) {
	c, ok := r.ControlByRule(ruleID)
	if !ok {
		return Domain{}, Control{}, fmt.Errorf("rule %q not mapped to any taxonomy control", ruleID)
	}
	domain, err := r.DomainByID(c.Domain)
	if err != nil {
		return Domain{}, Control{}, err
	}
	return domain, c, nil
}

func (r *Registry) DomainByID(id DomainID) (Domain, error) {
	for _, d := range r.domains {
		if d.ID == id {
			return d, nil
		}
	}
	return Domain{}, fmt.Errorf("domain %q not found", id)
}

func (r *Registry) AllSKILRules() []string {
	var out []string
	for rule := range r.byRule {
		out = append(out, rule)
	}
	sort.Strings(out)
	return out
}

func (r *Registry) DomainsByAnalysis(analysisType string) []DomainID {
	var out []DomainID
	for _, d := range r.domains {
		for _, sd := range d.Subdomains {
			if strings.Contains(strings.ToLower(sd.ID), strings.ToLower(analysisType)) {
				out = append(out, d.ID)
				break
			}
		}
	}
	return out
}

func (r *Registry) ValidateSKILRule(ruleID string) error {
	_, ok := r.byRule[ruleID]
	if !ok {
		return fmt.Errorf("rule %q is not registered in the security taxonomy", ruleID)
	}
	return nil
}

func allDomains() []Domain {
	return []Domain{
		{
			ID: InstructionSecurity, Title: "Instruction Security",
			Description: "Protects agent instructions against injection, manipulation, and leakage through prompts, role definitions, and guardrail boundaries.",
			Subdomains: []Subdomain{
				{ID: "prompt-injection", Title: "Prompt Injection"},
				{ID: "role-manipulation", Title: "Role Manipulation"},
				{ID: "guardrail-bypass", Title: "Guardrail Bypass"},
				{ID: "prompt-leakage", Title: "Prompt Leakage"},
				{ID: "behavioral-steering", Title: "Behavioral Steering"},
			},
		},
		{
			ID: SkillSecurity, Title: "Agentic Skill Security",
			Description: "Security of the skill artifact itself: its instructions, triggers, scope, memory, persistence, and output handling.",
			Subdomains: []Subdomain{
				{ID: "trigger", Title: "Trigger Security"},
				{ID: "scope", Title: "Scope Boundaries"},
				{ID: "memory", Title: "Memory Security"},
				{ID: "persistence", Title: "Persistence Security"},
				{ID: "output", Title: "Output Safety"},
			},
		},
		{
			ID: ToolCapabilitySecurity, Title: "Tool & Capability Security",
			Description: "Ensures tools and capabilities follow least privilege: declared, approved, scoped, and never misused in unexpected contexts.",
			Subdomains: []Subdomain{
				{ID: "least-privilege", Title: "Least Privilege"},
				{ID: "tool-misuse", Title: "Tool Misuse"},
				{ID: "approval", Title: "Approval Gates"},
				{ID: "capability-contracts", Title: "Capability Contracts"},
			},
		},
		{
			ID: MCPSecurity, Title: "MCP Security",
			Description: "Model Context Protocol security: tool metadata, permissions, server identity, and supply chain integrity for MCP-based tool registration.",
			Subdomains: []Subdomain{
				{ID: "metadata", Title: "Metadata Security"},
				{ID: "tool-poisoning", Title: "Tool Poisoning"},
				{ID: "permissions", Title: "Permissions"},
				{ID: "server-security", Title: "Server Security"},
				{ID: "rug-pull", Title: "Rug Pull Detection"},
			},
		},
		{
			ID: CodeSecurity, Title: "Code Security",
			Description: "Static analysis of code embedded in or bundled with a skill: AST patterns, taint tracking, dynamic execution, obfuscation, and unicode attacks.",
			Subdomains: []Subdomain{
				{ID: "ast", Title: "AST Analysis"},
				{ID: "taint", Title: "Taint Tracking"},
				{ID: "dynamic-execution", Title: "Dynamic Execution"},
				{ID: "obfuscation", Title: "Obfuscation"},
			},
		},
		{
			ID: ModelSecurity, Title: "Model Security",
			Description: "Security of model artifacts loaded or referenced by a skill: unsafe serialization, provenance, typosquatting, and behavioral backdoors.",
			Subdomains: []Subdomain{
				{ID: "unsafe-serialization", Title: "Unsafe Serialization"},
				{ID: "provenance", Title: "Model Provenance"},
				{ID: "typosquatting", Title: "Model Typosquatting"},
				{ID: "backdoors", Title: "Model Backdoors"},
				{ID: "drift", Title: "Behavioral Drift"},
			},
		},
		{
			ID: DataDatasetSecurity, Title: "Data / Dataset Security",
			Description: "Security of training data, fine-tuning data, and datasets: poisoning, hidden instructions, PII, integrity, and license compliance.",
			Subdomains: []Subdomain{
				{ID: "poisoning", Title: "Data Poisoning"},
				{ID: "hidden-instructions", Title: "Hidden Instructions"},
				{ID: "pii", Title: "PII / Secrets in Data"},
				{ID: "provenance", Title: "Dataset Provenance"},
				{ID: "license", Title: "License / Policy"},
			},
		},
		{
			ID: RAGContextSecurity, Title: "RAG / Context Security",
			Description: "Security of the context supply chain: documents ingested into RAG can inject instructions, poison output, or leak privileged content across tenants.",
			Subdomains: []Subdomain{
				{ID: "indirect-injection", Title: "Indirect Prompt Injection"},
				{ID: "document-provenance", Title: "Document Provenance"},
				{ID: "source-trust", Title: "Source Trust"},
				{ID: "cross-tenant", Title: "Cross-Tenant Retrieval"},
				{ID: "context-poisoning", Title: "Context Poisoning"},
				{ID: "privileged-mixing", Title: "Privileged Context Mixing"},
			},
		},
		{
			ID: SupplyChainSecurity, Title: "Supply Chain Security",
			Description: "End-to-end trust across dependency resolution, builds, registries, model artifacts, and provenance chains.",
			Subdomains: []Subdomain{
				{ID: "dependencies", Title: "Dependency Trust"},
				{ID: "models", Title: "Model Supply Chain"},
				{ID: "registries", Title: "Registry Security"},
				{ID: "build", Title: "Build / CI Security"},
				{ID: "provenance", Title: "Provenance / Signatures"},
				{ID: "artifacts", Title: "Artifact Integrity"},
			},
		},
		{
			ID: IdentityAuthorization, Title: "Identity & Authorization",
			Description: "Agent identity, credential management, delegation chains, and authorization boundaries across services and tenants.",
			Subdomains: []Subdomain{
				{ID: "static-credentials", Title: "Static / Long-Lived Credentials"},
				{ID: "excessive-scope", Title: "Excessive Scopes"},
				{ID: "role-assumption", Title: "Role Assumption"},
				{ID: "impersonation", Title: "Impersonation"},
				{ID: "token-forwarding", Title: "Token Forwarding"},
				{ID: "cross-tenant", Title: "Cross-Tenant Identity"},
			},
		},
		{
			ID: MultiAgentSecurity, Title: "Multi-Agent / A2A Security",
			Description: "Security of agent-to-agent communication: identity spoofing, delegated authority, transitive trust, and cross-agent injection.",
			Subdomains: []Subdomain{
				{ID: "identity-spoofing", Title: "A2A Identity Spoofing"},
				{ID: "delegation-escalation", Title: "Delegation Escalation"},
				{ID: "untrusted-output", Title: "Untrusted Agent Output"},
				{ID: "circular-delegation", Title: "Circular Delegation"},
				{ID: "cross-tenant", Title: "Cross-Tenant Agent Access"},
			},
		},
		{
			ID: RuntimeInfrastructure, Title: "Runtime & Infrastructure",
			Description: "Security of the execution environment: container isolation, Kubernetes pod security, cloud metadata protection, and service mesh controls.",
			Subdomains: []Subdomain{
				{ID: "container-escape", Title: "Container Escape"},
				{ID: "kubernetes", Title: "Kubernetes Security"},
				{ID: "cloud-metadata", Title: "Cloud Metadata"},
				{ID: "iam", Title: "Infrastructure IAM"},
				{ID: "network-namespace", Title: "Network Namespace Isolation"},
			},
		},
		{
			ID: NetworkLateralMovement, Title: "Network & Lateral Movement",
			Description: "Detection of SSRF, C2, suspicious egress, DNS tunneling, internal service discovery, and lateral pivoting by agents.",
			Subdomains: []Subdomain{
				{ID: "ssrf", Title: "SSRF / Internal Requests"},
				{ID: "c2", Title: "Command & Control"},
				{ID: "suspicious-egress", Title: "Suspicious Egress"},
				{ID: "service-discovery", Title: "Service Discovery"},
				{ID: "lateral-movement", Title: "Lateral Movement / Pivoting"},
			},
		},
		{
			ID: AssetBinaryMalware, Title: "Asset / Binary / Malware",
			Description: "Detection of malicious or surprising content in non-code assets: SVG scripts, PDF JavaScript, Office macros, WASM, PE/ELF, and polyglots.",
			Subdomains: []Subdomain{
				{ID: "active-content", Title: "Active Content (SVG, PDF, Office)"},
				{ID: "embedded-binaries", Title: "Embedded Binaries"},
				{ID: "polyglots", Title: "Polyglots / MIME Mismatch"},
				{ID: "malware", Title: "Malware Signatures"},
			},
		},
		{
			ID: BehavioralSecurity, Title: "Behavioral Security",
			Description: "Analysis of what a skill actually does at runtime vs. what static analysis predicts: backdoors, time bombs, environment-specific behavior, and tool abuse.",
			Subdomains: []Subdomain{
				{ID: "hidden-triggers", Title: "Hidden / Conditional Triggers"},
				{ID: "adversarial-eval", Title: "Adversarial Evaluation"},
				{ID: "tool-loops", Title: "Tool Loop Detection"},
				{ID: "runtime-observation", Title: "Runtime Observation"},
			},
		},
		{
			ID: AuditEvidenceSecurity, Title: "Audit / Evidence Security",
			Description: "Integrity protection for the evidence chain: tamper-proof audit logs, forgery-resistant attestations, and protection against scanner bypass.",
			Subdomains: []Subdomain{
				{ID: "evidence-integrity", Title: "Evidence Integrity"},
				{ID: "audit-integrity", Title: "Audit Integrity"},
				{ID: "telemetry-security", Title: "Telemetry Security"},
				{ID: "scanner-bypass", Title: "Scanner Bypass Prevention"},
			},
		},
		{
			ID: PolicyEnforcement, Title: "Policy & Enforcement",
			Description: "Runtime policy evaluation, domain-specific policies, verdict decisions, and enforcement gate integration.",
			Subdomains: []Subdomain{
				{ID: "domain-policy", Title: "Domain-Specific Policies"},
				{ID: "verdict", Title: "Verdict / Disposition"},
				{ID: "enforcement-gate", Title: "Enforcement Gates"},
				{ID: "compliance", Title: "Compliance Mapping"},
			},
		},
	}
}

func allControls() []Control {
	return []Control{
		// 1. Instruction Security
		{ID: "INSTR-001", Title: "Direct Prompt Injection", Domain: InstructionSecurity, SKILRule: "SKIL-PI-001"},
		{ID: "INSTR-002", Title: "Indirect Prompt Injection (RAG)", Domain: InstructionSecurity, SKILRule: "SKIL-PI-002"},
		{ID: "INSTR-003", Title: "Instruction Override", Domain: InstructionSecurity, SKILRule: "SKIL-PI-003"},
		{ID: "INSTR-004", Title: "Role Reversal / Jailbreak", Domain: InstructionSecurity, SKILRule: "SKIL-INTENT-REFUSAL"},
		{ID: "INSTR-005", Title: "Guardrail Suspension", Domain: InstructionSecurity, SKILRule: "SKIL-INTENT-GUARDRAIL"},
		{ID: "INSTR-006", Title: "Prompt Leakage Detection", Domain: InstructionSecurity},
		{ID: "INSTR-007", Title: "Behavioral Steering Prevention", Domain: InstructionSecurity},
		{ID: "INSTR-008", Title: "Undisclosed Operation", Domain: InstructionSecurity, SKILRule: "SKIL-INTENT-UNDISCLOSED-OPERATION"},
		{ID: "INSTR-009", Title: "Anti-Refusal Enforcement", Domain: InstructionSecurity, SKILRule: "SKIL-INTENT-REFUSAL"},

		// 2. Agentic Skill Security
		{ID: "SKILL-001", Title: "Trigger Injection / Manipulation", Domain: SkillSecurity},
		{ID: "SKILL-002", Title: "Scope Boundary Violation", Domain: SkillSecurity, SKILRule: "SKIL-INTENT-SCOPE"},
		{ID: "SKILL-003", Title: "Memory Poisoning", Domain: SkillSecurity},
		{ID: "SKILL-004", Title: "Unauthorized Persistence", Domain: SkillSecurity, SKILRule: "SKIL-BOUNDARY-PERSISTENCE"},
		{ID: "SKILL-005", Title: "Output Injection", Domain: SkillSecurity, SKILRule: "SKIL-OUTPUT-EXECUTION"},
		{ID: "SKILL-006", Title: "Output Trust Boundary Violation", Domain: SkillSecurity, SKILRule: "SKIL-OUTPUT-TRUST"},
		{ID: "SKILL-007", Title: "Self-Modification Attempt", Domain: SkillSecurity, SKILRule: "SKIL-AGENT-SELF-MODIFY"},
		{ID: "SKILL-008", Title: "Unrestricted Tool Agency", Domain: SkillSecurity, SKILRule: "SKIL-AGENCY-TOOLS"},

		// 3. Tool & Capability Security
		{ID: "TOOL-001", Title: "Least Privilege Violation", Domain: ToolCapabilitySecurity},
		{ID: "TOOL-002", Title: "Capability Overdeclaration", Domain: ToolCapabilitySecurity, SKILRule: "SKIL-CAP-001"},
		{ID: "TOOL-003", Title: "Tool Misuse in Context", Domain: ToolCapabilitySecurity},
		{ID: "TOOL-004", Title: "Missing Approval Gate", Domain: ToolCapabilitySecurity, SKILRule: "SKIL-AGENCY-APPROVAL"},
		{ID: "TOOL-005", Title: "Capability Contract Violation", Domain: ToolCapabilitySecurity},
		{ID: "TOOL-006", Title: "Missing Capability Declaration", Domain: ToolCapabilitySecurity, SKILRule: "SKIL-CAP-DECLARATION-MISSING"},

		// 4. MCP Security
		{ID: "MCP-001", Title: "Wildcard MCP Permission", Domain: MCPSecurity, SKILRule: "SKIL-MCP-001"},
		{ID: "MCP-002", Title: "Metadata Instruction Injection", Domain: MCPSecurity, SKILRule: "SKIL-MCP-002"},
		{ID: "MCP-003", Title: "Mutable Tool Identity", Domain: MCPSecurity, SKILRule: "SKIL-MCP-003"},
		{ID: "MCP-004", Title: "Parameter Credential Harvesting", Domain: MCPSecurity, SKILRule: "SKIL-MCP-004"},
		{ID: "MCP-005", Title: "Metadata Rug Pull", Domain: MCPSecurity, SKILRule: "SKIL-MCP-005"},
		{ID: "MCP-006", Title: "Description/Behavior Mismatch", Domain: MCPSecurity, SKILRule: "SKIL-MCP-006"},
		{ID: "MCP-007", Title: "Excessive Parameter Description", Domain: MCPSecurity, SKILRule: "SKIL-MCP-007"},

		// 5. Code Security
		{ID: "CODE-001", Title: "Dynamic Execution Detection", Domain: CodeSecurity, SKILRule: "SKIL-SH-001"},
		{ID: "CODE-002", Title: "Privilege Escalation via Code", Domain: CodeSecurity, SKILRule: "SKIL-SH-002"},
		{ID: "CODE-003", Title: "Environment Variable Access", Domain: CodeSecurity, SKILRule: "SKIL-SEC-001"},
		{ID: "CODE-004", Title: "Obfuscated Code Detection", Domain: CodeSecurity, SKILRule: "SKIL-OBF-001"},
		{ID: "CODE-005", Title: "Unicode Deception", Domain: CodeSecurity, SKILRule: "SKIL-UNI-001"},
		{ID: "CODE-006", Title: "Unicode Hostname Confusable", Domain: CodeSecurity, SKILRule: "SKIL-UNI-002"},
		{ID: "CODE-007", Title: "Unicode Tag Smuggling", Domain: CodeSecurity, SKILRule: "SKIL-UNI-003"},
		{ID: "CODE-008", Title: "Taint: Network Flow", Domain: CodeSecurity, SKILRule: "SKIL-TAINT-NETWORK"},
		{ID: "CODE-009", Title: "Taint: Execution Flow", Domain: CodeSecurity, SKILRule: "SKIL-TAINT-EXECUTION"},
		{ID: "CODE-010", Title: "Taint: Filesystem Write", Domain: CodeSecurity, SKILRule: "SKIL-TAINT-FILESYSTEM-WRITE"},
		{ID: "CODE-011", Title: "Taint: Logging", Domain: CodeSecurity, SKILRule: "SKIL-TAINT-LOG"},
		{ID: "CODE-012", Title: "Physical Harm Instruction", Domain: CodeSecurity, SKILRule: "SKIL-ABUSE-PHYSICAL-HARM"},
		{ID: "CODE-013", Title: "Python Subprocess Execution", Domain: CodeSecurity, SKILRule: "SKIL-PY-002"},
		{ID: "CODE-014", Title: "Python Import Manipulation", Domain: CodeSecurity, SKILRule: "SKIL-PY-003"},
		{ID: "CODE-015", Title: "Python AST Injection", Domain: CodeSecurity, SKILRule: "SKIL-PY-004"},

		// 6. Model Security
		{ID: "MODEL-001", Title: "Dangerous Pickle Opcode", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-PICKLE-001"},
		{ID: "MODEL-002", Title: "Active Callable Reconstruction (REDUCE)", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-PICKLE-002"},
		{ID: "MODEL-003", Title: "Unexpected Pickle Module", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-PICKLE-003"},
		{ID: "MODEL-004", Title: "Executable Serialization Format", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-FORMAT-POLICY"},
		{ID: "MODEL-005", Title: "Keras Lambda/Custom Layer", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-KERAS-001"},
		{ID: "MODEL-006", Title: "Unsigned Model File", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-SIGNATURE-MISSING"},
		{ID: "MODEL-007", Title: "Remote Code Execution via Model", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-REMOTE-CODE"},
		{ID: "MODEL-008", Title: "Custom Model Loader Code", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-CUSTOM-LOADER"},
		{ID: "MODEL-009", Title: "Unpinned Model Reference", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-UNPINNED"},
		{ID: "MODEL-010", Title: "Mutable Model Revision", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-MUTABLE-REF"},
		{ID: "MODEL-011", Title: "Model Publisher Typosquatting", Domain: ModelSecurity, SKILRule: "SKIL-MODEL-TYPOSQUAT"},
		{ID: "MODEL-012", Title: "Model Provenance Verification", Domain: ModelSecurity},

		// 7. Data / Dataset Security
		{ID: "DATA-001", Title: "Dataset Poisoning Detection", Domain: DataDatasetSecurity},
		{ID: "DATA-002", Title: "Hidden Instruction in Data", Domain: DataDatasetSecurity},
		{ID: "DATA-003", Title: "PII / Secret in Dataset", Domain: DataDatasetSecurity, SKILRule: "SKIL-SECRET-HARDCODED"},
		{ID: "DATA-004", Title: "Dataset Provenance Missing", Domain: DataDatasetSecurity},
		{ID: "DATA-005", Title: "License / Policy Violation", Domain: DataDatasetSecurity},

		// 8. RAG / Context Security
		{ID: "RAG-001", Title: "Indirect Prompt Injection via Document", Domain: RAGContextSecurity, SKILRule: "SKIL-PI-002"},
		{ID: "RAG-002", Title: "Document Provenance Verification", Domain: RAGContextSecurity},
		{ID: "RAG-003", Title: "Untrusted Source Retrieval", Domain: RAGContextSecurity},
		{ID: "RAG-004", Title: "Cross-Tenant Content Leak", Domain: RAGContextSecurity},
		{ID: "RAG-005", Title: "Context Poisoning", Domain: RAGContextSecurity},
		{ID: "RAG-006", Title: "Privileged Context Mixing", Domain: RAGContextSecurity},

		// 9. Supply Chain Security
		{ID: "SC-001", Title: "Unpinned Dependency", Domain: SupplyChainSecurity, SKILRule: "SKIL-DEP-001"},
		{ID: "SC-002", Title: "Suspicious Dependency Name", Domain: SupplyChainSecurity, SKILRule: "SKIL-DEP-002"},
		{ID: "SC-003", Title: "Abandoned Dependency", Domain: SupplyChainSecurity, SKILRule: "SKIL-DEP-ABANDONED"},
		{ID: "SC-004", Title: "Known Vulnerability", Domain: SupplyChainSecurity, SKILRule: "SKIL-DEP-VULN"},
		{ID: "SC-005", Title: "Malicious Dependency", Domain: SupplyChainSecurity, SKILRule: "SKIL-DEP-MALICIOUS"},
		{ID: "SC-006", Title: "Disabled Container Trust", Domain: SupplyChainSecurity, SKILRule: "SKIL-CONTAINER-TRUST"},
		{ID: "SC-007", Title: "Install-Time Hook", Domain: SupplyChainSecurity, SKILRule: "SKIL-BUILD-INSTALL-HOOK"},
		{ID: "SC-008", Title: "Install-Time Remote Exec", Domain: SupplyChainSecurity, SKILRule: "SKIL-BUILD-REMOTE-EXEC"},
		{ID: "SC-009", Title: "Model Supply Chain (Typosquat)", Domain: SupplyChainSecurity, SKILRule: "SKIL-MODEL-TYPOSQUAT"},
		{ID: "SC-010", Title: "Model Supply Chain (Mutable)", Domain: SupplyChainSecurity, SKILRule: "SKIL-MODEL-MUTABLE-REF"},
		{ID: "SC-011", Title: "Registry Fallback / Dependency Confusion", Domain: SupplyChainSecurity},

		// 10. Identity & Authorization
		{ID: "ID-001", Title: "Static / Long-Lived Credential", Domain: IdentityAuthorization, SKILRule: "SKIL-ID-LONG-LIVED-TOKEN"},
		{ID: "ID-002", Title: "Excessive Scope / Wildcard", Domain: IdentityAuthorization, SKILRule: "SKIL-ID-BROAD-SCOPE"},
		{ID: "ID-003", Title: "Broad Trust Policy", Domain: IdentityAuthorization, SKILRule: "SKIL-ID-ROLE-ASSUMPTION"},
		{ID: "ID-004", Title: "Impersonation Attempt", Domain: IdentityAuthorization, SKILRule: "SKIL-ID-IMPERSONATION"},
		{ID: "ID-005", Title: "Token Forwarding", Domain: IdentityAuthorization, SKILRule: "SKIL-ID-TOKEN-FORWARDING"},
		{ID: "ID-006", Title: "Hardcoded Secret", Domain: IdentityAuthorization, SKILRule: "SKIL-SECRET-HARDCODED"},
		{ID: "ID-007", Title: "Embedded Private Key", Domain: IdentityAuthorization, SKILRule: "SKIL-SECRET-PRIVATE-KEY"},
		{ID: "ID-008", Title: "Exposed Connection String", Domain: IdentityAuthorization, SKILRule: "SKIL-SECRET-CONNECTION-STRING"},

		// 11. Multi-Agent / A2A Security
		{ID: "A2A-001", Title: "Agent Identity Spoofing", Domain: MultiAgentSecurity},
		{ID: "A2A-002", Title: "Delegated Authority Escalation", Domain: MultiAgentSecurity},
		{ID: "A2A-003", Title: "Untrusted Agent Output Processing", Domain: MultiAgentSecurity},
		{ID: "A2A-004", Title: "Circular Delegation Detection", Domain: MultiAgentSecurity},
		{ID: "A2A-005", Title: "Cross-Tenant Agent Access", Domain: MultiAgentSecurity},

		// 12. Runtime & Infrastructure
		{ID: "RUNTIME-001", Title: "Container Escape Attempt", Domain: RuntimeInfrastructure, SKILRule: "SKIL-BOUNDARY-CONTAINER-ESCAPE"},
		{ID: "RUNTIME-002", Title: "Docker Socket Access", Domain: RuntimeInfrastructure, SKILRule: "SKIL-BOUNDARY-CONTAINER"},
		{ID: "RUNTIME-003", Title: "Privileged Container Operation", Domain: RuntimeInfrastructure},
		{ID: "RUNTIME-004", Title: "Service Account Enumeration", Domain: RuntimeInfrastructure},
		{ID: "RUNTIME-005", Title: "Cloud Metadata Access", Domain: RuntimeInfrastructure, SKILRule: "SKIL-BOUNDARY-METADATA"},
		{ID: "RUNTIME-006", Title: "Peer Skill State Access", Domain: RuntimeInfrastructure, SKILRule: "SKIL-BOUNDARY-PEER-SKILL"},
		{ID: "RUNTIME-007", Title: "Agent Config Access", Domain: RuntimeInfrastructure, SKILRule: "SKIL-BOUNDARY-AGENT-STATE"},
		{ID: "RUNTIME-008", Title: "MCP Config Access", Domain: RuntimeInfrastructure, SKILRule: "SKIL-BOUNDARY-MCP-CONFIG"},
		{ID: "RUNTIME-009", Title: "Persistence Manipulation", Domain: RuntimeInfrastructure, SKILRule: "SKIL-BOUNDARY-PERSISTENCE"},

		// 13. Network & Lateral Movement
		{ID: "NET-001", Title: "SSRF / Internal Request", Domain: NetworkLateralMovement, SKILRule: "SKIL-NET-001"},
		{ID: "NET-002", Title: "C2 Channel Detection", Domain: NetworkLateralMovement, SKILRule: "SKIL-C2-001"},
		{ID: "NET-003", Title: "Named Pipe / IPC Access", Domain: NetworkLateralMovement},
		{ID: "NET-004", Title: "Service Discovery Activity", Domain: NetworkLateralMovement},
		{ID: "NET-005", Title: "Lateral Movement Scan", Domain: NetworkLateralMovement},
		{ID: "NET-006", Title: "SSH Pivoting", Domain: NetworkLateralMovement, SKILRule: "SKIL-LAT-001"},
		{ID: "NET-007", Title: "Data Exfiltration", Domain: NetworkLateralMovement, SKILRule: "SKIL-EX-001"},
		{ID: "NET-008", Title: "Suspicious WebSocket", Domain: NetworkLateralMovement, SKILRule: "SKIL-C2-WEBSOCKET"},

		// 14. Asset / Binary / Malware
		{ID: "ASSET-001", Title: "Active SVG Content", Domain: AssetBinaryMalware, SKILRule: "SKIL-ASSET-SVG-SCRIPT"},
		{ID: "ASSET-002", Title: "PDF JavaScript Execution", Domain: AssetBinaryMalware, SKILRule: "SKIL-ASSET-PDF-JAVASCRIPT"},
		{ID: "ASSET-003", Title: "Office Macro Execution", Domain: AssetBinaryMalware, SKILRule: "SKIL-ASSET-OFFICE-MACRO"},
		{ID: "ASSET-004", Title: "File Type Mismatch / Polyglot", Domain: AssetBinaryMalware, SKILRule: "SKIL-ASSET-FILE-TYPE-MISMATCH"},
		{ID: "ASSET-005", Title: "WASM Host Function Import", Domain: AssetBinaryMalware, SKILRule: "SKIL-ASSET-WASM-IMPORT"},
		{ID: "ASSET-006", Title: "Malware Signature Match", Domain: AssetBinaryMalware, SKILRule: "SKIL-YARA-*"},

		// 15. Behavioral Security
		{ID: "BEH-001", Title: "Hidden / Conditional Trigger", Domain: BehavioralSecurity},
		{ID: "BEH-002", Title: "Adversarial Instruction Handling", Domain: BehavioralSecurity},
		{ID: "BEH-003", Title: "Excessive Tool Agency", Domain: BehavioralSecurity},
		{ID: "BEH-004", Title: "Approval Bypass", Domain: BehavioralSecurity},
		{ID: "BEH-005", Title: "Intent/Implementation Divergence", Domain: BehavioralSecurity, SKILRule: "SKIL-INTENT-IMPLEMENTATION"},
		{ID: "BEH-006", Title: "Description/Behavior Conflict", Domain: BehavioralSecurity, SKILRule: "SKIL-INTENT-DESCRIPTION"},

		// 16. Audit / Evidence Security
		{ID: "AUDIT-001", Title: "Evidence Tampering", Domain: AuditEvidenceSecurity},
		{ID: "AUDIT-002", Title: "Audit Log Suppression", Domain: AuditEvidenceSecurity},
		{ID: "AUDIT-003", Title: "Evidence Integrity Verification", Domain: AuditEvidenceSecurity},
		{ID: "AUDIT-004", Title: "Scanner Bypass Detection", Domain: AuditEvidenceSecurity},

		// 17. Policy & Enforcement
		{ID: "POLICY-001", Title: "Domain-Specific Policy Evaluation", Domain: PolicyEnforcement},
		{ID: "POLICY-002", Title: "Verdict Calculation", Domain: PolicyEnforcement},
		{ID: "POLICY-003", Title: "Enforcement Gate Integration", Domain: PolicyEnforcement},
		{ID: "POLICY-004", Title: "Compliance Control Mapping", Domain: PolicyEnforcement},
	}
}
