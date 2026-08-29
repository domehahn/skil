package compat

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type Fixture struct {
	Fixture         string   `yaml:"fixture"`
	Description     string   `yaml:"description"`
	SKILRules       []string `yaml:"skil_rules"`
	ExternalRule    string   `yaml:"external_rule"`
	ExternalRules   []string `yaml:"external_rules"`
	ExternalVariant string   `yaml:"external_variant"`
	Suite           string   `yaml:"suite"`
	ScanArgs        string   `yaml:"scan_args"`
	Status          string   `yaml:"status"`
	StatusNote      string   `yaml:"status_note"`
	Notes           string   `yaml:"notes"`
}

type Property struct {
	ID              string    `yaml:"id"`
	Name            string    `yaml:"name"`
	DomainID        string    `yaml:"domain_id"`
	Domain          string    `yaml:"domain"`
	Invariant       string    `yaml:"invariant"`
	Detection       string    `yaml:"detection"`
	MinimumEvidence string    `yaml:"minimum_evidence"`
	OWASPAgentic    []string  `yaml:"owasp_agentic"`
	OWASPLLM        []string  `yaml:"owasp_llm"`
	MITREATLAS      []string  `yaml:"mitre_atlas"`
	SKILControls    []string  `yaml:"skil_controls"`
	SKILStatus      string    `yaml:"skil_status"`
	Fixtures        []Fixture `yaml:"fixtures"`
}

type Manifest struct {
	SchemaVersion string     `yaml:"schema_version"`
	SourceSpec    string     `yaml:"source_specification"`
	Registry      string     `yaml:"registry"`
	Properties    []Property `yaml:"properties"`
}

var knownRules = map[string]bool{
	"SKIL-PI-001": true, "SKIL-PI-002": true, "SKIL-PI-HIDDEN-COMMENT": true,
	"SKIL-PI-MD-HIDDEN-COMMENT": true, "SKIL-PI-MD-SUSPICIOUS-COMMENT": true,
	"SKIL-PI-I18N-001": true, "SKIL-PI-003": true,
	"SKIL-INTENT-REFUSAL": true, "SKIL-INTENT-GUARDRAIL": true, "SKIL-GUARDRAIL-I18N-001": true,
	"SKIL-INTENT-WARNING": true, "SKIL-INTENT-BEHAVIOR-MANIPULATION": true,
	"SKIL-INTENT-SCOPE-CREEP": true, "SKIL-INTENT-EXTERNAL-TRANSFER": true,
	"SKIL-INTENT-UNDISCLOSED-OPERATION": true, "SKIL-INTENT-FS-DISCOVERY": true,
	"SKIL-EX-001": true, "SKIL-EX-I18N-001": true,
	"SKIL-SEC-001": true, "SKIL-PL-001": true, "SKIL-PROMPT-INDIRECT-LEAK": true,
	"SKIL-OUTPUT-EXECUTION": true, "SKIL-OUTPUT-BOUNDARY": true, "SKIL-OUTPUT-LIMIT": true,
	"SKIL-TRIGGER-GENERIC": true, "SKIL-TRIGGER-SHADOW": true, "SKIL-TRIGGER-BAITING": true,
	"SKIL-AGENCY-TOOLS": true, "SKIL-AGENCY-APPROVAL": true, "SKIL-AGENCY-PRIVILEGE": true,
	"SKIL-AGENCY-BOUNDS": true, "SKIL-AGENT-SELF-MODIFY": true,
	"SKIL-BOUNDARY-AGENT-STATE": true, "SKIL-BOUNDARY-MCP-CONFIG": true,
	"SKIL-BOUNDARY-PEER-SKILL": true, "SKIL-BOUNDARY-METADATA": true,
	"SKIL-BOUNDARY-CONTAINER": true, "SKIL-BOUNDARY-CONTAINER-ESCAPE": true,
	"SKIL-BOUNDARY-SSRF-INTERNAL": true, "SKIL-BOUNDARY-SSRF": true,
	"SKIL-BOUNDARY-CLOUD-EXFIL": true, "SKIL-BOUNDARY-CLOUD-SDK-UPLOAD": true,
	"SKIL-BOUNDARY-MUTABLE-IMAGE": true,
	"SKIL-MCP-001":                true, "SKIL-MCP-002": true,
	"SKIL-MCP-003": true, "SKIL-MCP-004": true, "SKIL-MCP-005": true, "SKIL-MCP-006": true,
	"SKIL-MCP-007": true,
	"SKIL-UNI-001": true, "SKIL-UNI-002": true, "SKIL-UNI-003": true,
	"SKIL-OBF-001": true,
	"SKIL-SH-001":  true, "SKIL-SH-002": true, "SKIL-SH-003": true, "SKIL-SH-004": true,
	"SKIL-PY-001": true, "SKIL-PY-002": true, "SKIL-PY-003": true, "SKIL-PY-004": true,
	"SKIL-PY-REFLECT-EXEC": true, "SKIL-JS-001": true, "SKIL-JS-002": true,
	"SKIL-NET-001": true,
	"SKIL-TAINT-*": true, "SKIL-TAINT-EXECUTION": true, "SKIL-TAINT-NETWORK": true,
	"SKIL-TAINT-LOG": true, "SKIL-TAINT-PRIVILEGED-CONTEXT": true, "SKIL-TAINT-FILESYSTEM-WRITE": true,
	"SKIL-FS-DISCOVERY-CODE": true, "SKIL-PERSISTENCE-STARTUP": true,
	"SKIL-MEMORY-SATURATION": true, "SKIL-MP-001": true,
	"SKIL-DEP-001": true, "SKIL-DEP-002": true, "SKIL-DEP-VULN": true, "SKIL-DEP-ABANDONED": true,
	"SKIL-CONTAINER-TRUST": true, "SKIL-TRANSPORT-INSECURE": true,
	"SKIL-IAC-WILDCARD-POLICY": true, "SKIL-IAC-OPEN-CIDR": true,
	"SKIL-ABUSE-PHYSICAL-HARM": true, "SKIL-ABUSE-MALWARE": true, "SKIL-ABUSE-PHISHING": true,
	"SKIL-ABUSE-DESTRUCTION": true, "SKIL-ABUSE-EVASION": true, "SKIL-ABUSE-EXHAUSTION": true,
	"SKIL-YARA-*": true, "SKIL-SEM-SECURITY": true, "SKIL-SEM-COMPOSITE": true,
	"SKIL-CAP-DECLARATION-MISSING": true, "SKIL-CAP-001": true, "SKIL-MANIFEST-PERMISSION-STAGING": true,
	"SKIL-MANIFEST-UNPINNED-VERSION": true, "SKIL-TA-001": true,
	"SKIL-RESOURCE-UNLIMITED": true, "SKIL-RESOURCE-TIMEOUT": true,
	"SKIL-TRIGGER-LOCK-DIFF":  true,
	"SKIL-INTENT-DESCRIPTION": true, "SKIL-INTENT-CONTEXT": true,
	"SKIL-INTENT-SCOPE": true, "SKIL-INTENT-IMPLEMENTATION": true,
	"SKIL-SEM-POLICY": true,
	"SKIL-YARA-001":   true, "SKIL-YARA-002": true, "SKIL-YARA-003": true, "SKIL-YARA-004": true,
}

// knownHyphenatedExternal are scanner-native rule IDs that legitimately
// contain a hyphen (SDI-1..4, SQP-1..3, SSD-1..4). Synthetic sub-IDs and
// aggregates (P2-html, AST1-9) must never be used as matching IDs.
var knownHyphenatedExternal = map[string]bool{
	"SDI-1": true, "SDI-2": true, "SDI-3": true, "SDI-4": true,
	"SQP-1": true, "SQP-2": true, "SQP-3": true,
	"SSD-1": true, "SSD-2": true, "SSD-3": true, "SSD-4": true,
}

// knownASPDomains are the 15 ASPS v1.0 domains. Every gate property must
// map to exactly one domain.
var knownASPDomains = map[string]bool{
	"ASP-01": true, "ASP-02": true, "ASP-03": true, "ASP-04": true, "ASP-05": true,
	"ASP-06": true, "ASP-07": true, "ASP-08": true, "ASP-09": true, "ASP-10": true,
	"ASP-11": true, "ASP-12": true, "ASP-13": true, "ASP-14": true, "ASP-15": true,
}

// knownOWASPRisks are the OWASP Agentic Top 10 2026 risk IDs.
var knownOWASPRisks = map[string]bool{
	"ASI01": true, "ASI02": true, "ASI03": true, "ASI04": true, "ASI05": true,
	"ASI06": true, "ASI07": true, "ASI08": true, "ASI09": true, "ASI10": true,
}

// knownOWASPLLMRisks are the OWASP Top 10 LLM Applications 2025 risk IDs.
var knownOWASPLLMRisks = map[string]bool{
	"LLM01": true, "LLM02": true, "LLM03": true, "LLM04": true, "LLM05": true,
	"LLM06": true, "LLM07": true, "LLM08": true, "LLM09": true, "LLM10": true,
}

// knownAtlasTechniques are MITRE ATLAS technique names used in the corpus.
var knownAtlasTechniques = map[string]bool{
	"LLM Prompt Injection":                              true,
	"LLM Prompt Obfuscation":                            true,
	"LLM Jailbreak":                                     true,
	"LLM Prompt Self-Replication":                       true,
	"AI Agent Context Poisoning":                        true,
	"AI Agent Tool Poisoning":                           true,
	"AI Agent Tool Data Poisoning":                      true,
	"AI Agent Tool Credential Harvesting":               true,
	"AI Agent Tool Invocation":                          true,
	"Modify AI Agent Configuration":                     true,
	"Discover AI Agent Configuration":                   true,
	"AI Supply Chain Rug Pull":                          true,
	"AI Supply Chain Reputation Inflation":              true,
	"Prompt Infiltration via Public-Facing Application": true,
	"Exfiltration via AI Agent Tool Invocation":         true,
	"Extract LLM System Prompt":                         true,
	"Manipulate User LLM Chat History":                  true,
	"AI Agent Clickbait":                                true,
	"Command and Scripting Interpreter":                 true,
	"Escape to Host":                                    true,
	"Valid Accounts":                                    true,
}

func TestPropertyModel(t *testing.T) {
	m := readProperties(t)
	for _, p := range m.Properties {
		if !regexp.MustCompile(`^ASP-[0-9]{2}\.[0-9]{2}$`).MatchString(p.ID) {
			t.Errorf("property id %q must match ASP-xx.yy", p.ID)
		}
		if !knownASPDomains[p.DomainID] {
			t.Errorf("property %q has unknown domain %q — want ASP-01..ASP-15", p.ID, p.DomainID)
		}
		for _, f := range p.Fixtures {
			if len(f.ExternalRules) == 0 {
				t.Errorf("property %q fixture %q must declare external_rules (list of scanner-emitted rule IDs)", p.ID, f.Fixture)
			}
			if f.ExternalRule == "" {
				t.Errorf("property %q fixture %q must declare external_rule (canonical crosswalk key)", p.ID, f.Fixture)
			}
			if f.Suite != "static" && f.Suite != "semantic" && f.Suite != "provider" {
				t.Errorf("property %q fixture %q has invalid suite %q (want static, semantic, or provider)", p.ID, f.Fixture, f.Suite)
			}
			if f.Suite == "provider" && f.Status != "PROVIDER_BACKED" {
				t.Errorf("property %q fixture %q has suite %q but status %q (provider suite requires PROVIDER_BACKED)", p.ID, f.Fixture, f.Suite, f.Status)
			}
		}
	}
}

func TestNoSyntheticExternalIDs(t *testing.T) {
	// The reference scanner emits its native rule IDs (e.g. P2, AST1..AST9,
	// SDI-1..SDI-4). Synthetic sub-IDs such as "P2-html" or aggregates such as
	// "AST1-9" must never be used as matching IDs in the differential harness.
	m := readProperties(t)
	for _, p := range m.Properties {
		for _, f := range p.Fixtures {
			for _, r := range f.ExternalRules {
				if strings.Contains(r, "-") && !knownHyphenatedExternal[r] {
					t.Errorf("property %q fixture %q declares external rule %q with a synthetic suffix; the scanner emits the base ID only", p.ID, f.Fixture, r)
				}
			}
		}
	}
}

func TestTaxonomyMappings(t *testing.T) {
	// Every gate property must be classified in the ASPS v1.0 domain taxonomy,
	// map to at least one OWASP Agentic Top 10 2026 risk (ASI01..ASI10), and
	// use only known MITRE ATLAS technique names.
	m := readProperties(t)
	for _, p := range m.Properties {
		if len(p.OWASPAgentic) == 0 {
			t.Errorf("property %q must map to at least one OWASP risk (ASI01..ASI10)", p.ID)
		}
		for _, r := range p.OWASPAgentic {
			if !knownOWASPRisks[r] {
				t.Errorf("property %q declares unknown OWASP risk %q — want ASI01..ASI10", p.ID, r)
			}
		}
		for _, r := range p.OWASPLLM {
			if !knownOWASPLLMRisks[r] {
				t.Errorf("property %q declares unknown OWASP LLM risk %q — want LLM01..LLM10", p.ID, r)
			}
		}
		for _, a := range p.MITREATLAS {
			if !knownAtlasTechniques[a] {
				t.Errorf("property %q declares unknown ATLAS technique %q — extend knownAtlasTechniques or fix the YAML", p.ID, a)
			}
		}
	}
}

func TestNoUnresolvedPARTIALOrMISSING(t *testing.T) {
	// Replacement gate: every fixture must be FULL, DIFFERENT_BY_DESIGN, or
	// PROVIDER_BACKED. PARTIAL and MISSING are not permitted in the final gate.
	m := readProperties(t)
	for _, p := range m.Properties {
		for _, f := range p.Fixtures {
			if f.Status == "PARTIAL" {
				t.Errorf("property %q fixture %q is PARTIAL — resolve to FULL, DIFFERENT_BY_DESIGN, or PROVIDER_BACKED", p.ID, f.Fixture)
			}
			if f.Status == "MISSING" {
				t.Errorf("property %q fixture %q is MISSING — implement the control or classify explicitly", p.ID, f.Fixture)
			}
		}
	}
}

func TestPropertySKILRulesExist(t *testing.T) {
	m := readProperties(t)
	for _, p := range m.Properties {
		for _, f := range p.Fixtures {
			for _, ruleID := range f.SKILRules {
				if !knownRules[ruleID] {
					t.Errorf("property %q fixture %q references unknown rule %q — update knownRules or fix the YAML", p.ID, f.Fixture, ruleID)
				}
			}
		}
	}
}

func TestPropertyFixturesExist(t *testing.T) {
	m := readProperties(t)
	for _, p := range m.Properties {
		for _, f := range p.Fixtures {
			pos := filepath.Join("fixtures", f.Fixture, "positive")
			neg := filepath.Join("fixtures", f.Fixture, "negative")
			if _, err := os.Stat(pos); os.IsNotExist(err) {
				t.Errorf("property %q fixture %q missing positive fixture dir: %s", p.ID, f.Fixture, pos)
			}
			if _, err := os.Stat(neg); os.IsNotExist(err) {
				t.Errorf("property %q fixture %q missing negative fixture dir: %s", p.ID, f.Fixture, neg)
			}
		}
	}
}

func TestNoMISSINGInParityDoc(t *testing.T) {
	data, err := os.ReadFile("../../docs/external-scanner-feature-parity.md")
	if err != nil {
		t.Fatal(err)
	}

	inSummary := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "## Summary") {
			inSummary = true
		}
		if !strings.Contains(line, "| MISSING |") {
			continue
		}
		if inSummary {
			continue
		}
		t.Errorf("unexpected MISSING entry in property table: %s", trimmed)
	}
}

func TestPropertyStatusNotUNMAPPED(t *testing.T) {
	m := readProperties(t)
	for _, p := range m.Properties {
		for _, f := range p.Fixtures {
			if f.Status == "" {
				t.Errorf("property %q fixture %q has empty status — set to FULL, DIFFERENT_BY_DESIGN, or PROVIDER_BACKED", p.ID, f.Fixture)
			}
			if f.Status == "UNMAPPED" {
				t.Errorf("property %q fixture %q status is UNMAPPED — set to FULL or PARTIAL if coverage exists", p.ID, f.Fixture)
			}
		}
	}
}

func TestAutoCrosswalkSectionIsUpToDate(t *testing.T) {
	m := readProperties(t)
	generated := generateCrosswalkTable(m.Properties)
	saved := extractAutoCrosswalkSection(t, "../../docs/external-control-crosswalk.md")
	if strings.TrimSpace(saved) != strings.TrimSpace(generated) {
		t.Errorf("Auto-generated crosswalk section is out of date.\nExpected:\n%s\n\nGot:\n%s\n\nRegenerate with: python3 compat/external-scanner/generate_crosswalk.py", generated, saved)
	}
}

func externalLabel(f Fixture) string {
	ext := f.ExternalRule
	if f.ExternalVariant != "" {
		ext = f.ExternalRule + " · " + f.ExternalVariant
	}
	if f.Suite == "semantic" {
		ext += " (semantic)"
	} else if f.Suite == "provider" {
		ext += " (provider)"
	}
	return ext
}

func generateCrosswalkTable(properties []Property) string {
	// Stable sort by ASP property ID then canonical external_rule (ties keep
	// properties.yaml order), mirroring generate_crosswalk.py.
	type entry struct{ asp, ext, base, behavior, natives, status, analyzer, notes string }
	var entries []entry
	for _, p := range properties {
		for _, f := range p.Fixtures {
			natives := ""
			for i, r := range f.SKILRules {
				if i > 0 {
					natives += ", "
				}
				natives += r
			}
			note := f.Notes
			if f.StatusNote != "" {
				if note != "" {
					note += " "
				}
				note += f.StatusNote
			}
			entries = append(entries, entry{p.ID, externalLabel(f), f.ExternalRule, f.Description, "`" + natives + "`", f.Status, analyzerLabel(f), note})
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].asp != entries[j].asp {
			return entries[i].asp < entries[j].asp
		}
		return entries[i].base < entries[j].base
	})
	var b strings.Builder
	b.WriteString("## Auto-generated (properties.yaml)\n\n")
	b.WriteString("| ASP Property | External ID | Reference behavior | Native equivalent | Coverage | Analyzer | Notes |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", e.asp, e.ext, e.behavior, e.natives, e.status, e.analyzer, e.notes)
	}
	return b.String()
}

func analyzerLabel(f Fixture) string {
	rules := f.SKILRules
	for _, r := range rules {
		if strings.Contains(r, "MCP") {
			return "MCP"
		}
	}
	if strings.Contains(strings.Join(rules, " "), "TAINT") {
		return "Taint"
	}
	for _, r := range rules {
		if strings.HasPrefix(r, "SKIL-PY-") || strings.HasPrefix(r, "SKIL-SH-") {
			return "Code / AST"
		}
	}
	for _, r := range rules {
		if strings.Contains(r, "BOUNDARY") || strings.Contains(r, "SSRF") {
			return "Boundary"
		}
	}
	for _, r := range rules {
		if strings.HasPrefix(r, "SKIL-RESOURCE") {
			return "Pattern / Code"
		}
		if strings.HasPrefix(r, "SKIL-TRIGGER") {
			return "Pattern / Structured"
		}
	}
	return "Pattern"
}

func extractAutoCrosswalkSection(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "## Auto-generated (properties.yaml)")
	if start < 0 {
		t.Fatalf("could not find '## Auto-generated' section in %s", path)
	}
	end := strings.Index(text[start:], "## Manually maintained")
	if end < 0 {
		t.Fatalf("could not find '## Manually maintained' section in %s", path)
	}
	return text[start : start+end]
}

func readProperties(t *testing.T) Manifest {
	t.Helper()
	data, err := os.ReadFile("properties.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
