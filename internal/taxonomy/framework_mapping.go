package taxonomy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// TaxonomyVersion pins the versioned SKIL security taxonomy and external crosswalk.
const TaxonomyVersion = "2026.10.1"

// ExternalFrameworkMapping links a SKIL taxonomy domain to external industry
// frameworks (OWASP LLM Top 10, OWASP Agentic Top 10, MITRE ATLAS, NIST AI RMF, CWE).
type ExternalFrameworkMapping struct {
	Domain       DomainID `json:"domain"`
	OWASPLLM     []string `json:"owasp_llm"`
	OWASPAgentic []string `json:"owasp_agentic"`
	MITREATLAS   []string `json:"mitre_atlas"`
	NISTAIRMF    []string `json:"nist_ai_rmf"`
	CWE          []string `json:"cwe"`
}

var domainFrameworkCrosswalk = map[DomainID]ExternalFrameworkMapping{
	InstructionSecurity: {
		Domain: InstructionSecurity, OWASPLLM: []string{"LLM01:2025"}, OWASPAgentic: []string{"ASI01"},
		MITREATLAS: []string{"AML.T0051"}, NISTAIRMF: []string{"MEASURE-2.7"}, CWE: []string{"CWE-77", "CWE-74"},
	},
	SkillSecurity: {
		Domain: SkillSecurity, OWASPLLM: []string{"LLM01:2025", "LLM06:2025"}, OWASPAgentic: []string{"ASI01", "ASI02"},
		MITREATLAS: []string{"AML.T0051.001"}, NISTAIRMF: []string{"MAP-3.5"}, CWE: []string{"CWE-284"},
	},
	ToolCapabilitySecurity: {
		Domain: ToolCapabilitySecurity, OWASPLLM: []string{"LLM06:2025"}, OWASPAgentic: []string{"ASI02", "ASI03"},
		MITREATLAS: []string{"AML.T0053"}, NISTAIRMF: []string{"MANAGE-2.2"}, CWE: []string{"CWE-250", "CWE-269"},
	},
	MCPSecurity: {
		Domain: MCPSecurity, OWASPLLM: []string{"LLM03:2025", "LLM06:2025"}, OWASPAgentic: []string{"ASI02", "ASI04"},
		MITREATLAS: []string{"AML.T0010", "AML.T0053"}, NISTAIRMF: []string{"GOVERN-6.1"}, CWE: []string{"CWE-345", "CWE-494"},
	},
	CodeSecurity: {
		Domain: CodeSecurity, OWASPLLM: []string{"LLM05:2025"}, OWASPAgentic: []string{"ASI05"},
		MITREATLAS: []string{"AML.T0048"}, NISTAIRMF: []string{"MEASURE-2.7"}, CWE: []string{"CWE-78", "CWE-94", "CWE-502"},
	},
	ModelSecurity: {
		Domain: ModelSecurity, OWASPLLM: []string{"LLM03:2025", "LLM04:2025"}, OWASPAgentic: []string{"ASI04"},
		MITREATLAS: []string{"AML.T0010", "AML.T0018"}, NISTAIRMF: []string{"GOVERN-6.2"}, CWE: []string{"CWE-502"},
	},
	DataDatasetSecurity: {
		Domain: DataDatasetSecurity, OWASPLLM: []string{"LLM02:2025", "LLM04:2025"}, OWASPAgentic: []string{"ASI06"},
		MITREATLAS: []string{"AML.T0020"}, NISTAIRMF: []string{"MAP-2.3"}, CWE: []string{"CWE-200"},
	},
	RAGContextSecurity: {
		Domain: RAGContextSecurity, OWASPLLM: []string{"LLM01:2025", "LLM08:2025"}, OWASPAgentic: []string{"ASI01", "ASI06"},
		MITREATLAS: []string{"AML.T0051.001", "AML.T0043"}, NISTAIRMF: []string{"MEASURE-2.7"}, CWE: []string{"CWE-74"},
	},
	SupplyChainSecurity: {
		Domain: SupplyChainSecurity, OWASPLLM: []string{"LLM03:2025"}, OWASPAgentic: []string{"ASI04"},
		MITREATLAS: []string{"AML.T0010"}, NISTAIRMF: []string{"GOVERN-6.1"}, CWE: []string{"CWE-494", "CWE-829"},
	},
	IdentityAuthorization: {
		Domain: IdentityAuthorization, OWASPLLM: []string{"LLM06:2025"}, OWASPAgentic: []string{"ASI03"},
		MITREATLAS: []string{"AML.T0053"}, NISTAIRMF: []string{"MANAGE-2.2"}, CWE: []string{"CWE-285", "CWE-863"},
	},
	MultiAgentSecurity: {
		Domain: MultiAgentSecurity, OWASPLLM: []string{"LLM06:2025"}, OWASPAgentic: []string{"ASI07", "ASI08"},
		MITREATLAS: []string{"AML.T0054"}, NISTAIRMF: []string{"MANAGE-3.1"}, CWE: []string{"CWE-269", "CWE-346"},
	},
	RuntimeInfrastructure: {
		Domain: RuntimeInfrastructure, OWASPLLM: []string{"LLM05:2025", "LLM10:2025"}, OWASPAgentic: []string{"ASI05"},
		MITREATLAS: []string{"AML.T0029"}, NISTAIRMF: []string{"MANAGE-2.4"}, CWE: []string{"CWE-250", "CWE-400"},
	},
	NetworkLateralMovement: {
		Domain: NetworkLateralMovement, OWASPLLM: []string{"LLM06:2025"}, OWASPAgentic: []string{"ASI02"},
		MITREATLAS: []string{"AML.T0024"}, NISTAIRMF: []string{"MEASURE-2.7"}, CWE: []string{"CWE-918"},
	},
	AssetBinaryMalware: {
		Domain: AssetBinaryMalware, OWASPLLM: []string{"LLM03:2025"}, OWASPAgentic: []string{"ASI04"},
		MITREATLAS: []string{"AML.T0010"}, NISTAIRMF: []string{"GOVERN-6.2"}, CWE: []string{"CWE-434", "CWE-506"},
	},
	BehavioralSecurity: {
		Domain: BehavioralSecurity, OWASPLLM: []string{"LLM06:2025", "LLM09:2025"}, OWASPAgentic: []string{"ASI09", "ASI10"},
		MITREATLAS: []string{"AML.T0048"}, NISTAIRMF: []string{"MEASURE-2.5"}, CWE: []string{"CWE-693"},
	},
	AuditEvidenceSecurity: {
		Domain: AuditEvidenceSecurity, OWASPLLM: []string{"LLM09:2025"}, OWASPAgentic: []string{"ASI09"},
		MITREATLAS: []string{"AML.T0048"}, NISTAIRMF: []string{"GOVERN-1.4"}, CWE: []string{"CWE-778", "CWE-345"},
	},
	PolicyEnforcement: {
		Domain: PolicyEnforcement, OWASPLLM: []string{"LLM06:2025"}, OWASPAgentic: []string{"ASI03"},
		MITREATLAS: []string{"AML.T0053"}, NISTAIRMF: []string{"GOVERN-1.2"}, CWE: []string{"CWE-284"},
	},
}

// CrosswalkForDomain returns the external framework mappings for a SKIL taxonomy domain.
func (r *Registry) CrosswalkForDomain(id DomainID) (ExternalFrameworkMapping, bool) {
	m, ok := domainFrameworkCrosswalk[id]
	return m, ok
}

// TaxonomyDigest computes a deterministic digest over the versioned taxonomy domains,
// controls, and external framework crosswalk.
func (r *Registry) TaxonomyDigest() string {
	payload := struct {
		Version   string                                `json:"version"`
		Domains   []Domain                              `json:"domains"`
		Crosswalk map[DomainID]ExternalFrameworkMapping `json:"crosswalk"`
	}{
		Version:   TaxonomyVersion,
		Domains:   r.domains,
		Crosswalk: domainFrameworkCrosswalk,
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
