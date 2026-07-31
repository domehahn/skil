package compat

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type Property struct {
	ID           string   `yaml:"id"`
	Description  string   `yaml:"description"`
	Fixture      string   `yaml:"fixture"`
	SKILRules    []string `yaml:"skil_rules"`
	ExternalRule string   `yaml:"external_rule"`
	Status       string   `yaml:"status"`
	Notes        string   `yaml:"notes"`
}

type Manifest struct {
	SchemaVersion string     `yaml:"schema_version"`
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
	"SKIL-MCP-001": true, "SKIL-MCP-002": true,
	"SKIL-MCP-003": true, "SKIL-MCP-004": true, "SKIL-MCP-005": true, "SKIL-MCP-006": true,
	"SKIL-MCP-007": true,
	"SKIL-UNI-001": true, "SKIL-UNI-002": true, "SKIL-UNI-003": true,
	"SKIL-OBF-001": true,
	"SKIL-SH-001": true, "SKIL-SH-002": true, "SKIL-SH-003": true, "SKIL-SH-004": true,
	"SKIL-PY-001": true, "SKIL-PY-002": true, "SKIL-PY-003": true, "SKIL-PY-004": true,
	"SKIL-PY-REFLECT-EXEC": true, "SKIL-JS-001": true, "SKIL-JS-002": true,
	"SKIL-NET-001": true,
	"SKIL-TAINT-EXECUTION": true, "SKIL-TAINT-NETWORK": true,
	"SKIL-TAINT-LOG": true, "SKIL-TAINT-PRIVILEGED-CONTEXT": true,
	"SKIL-FS-DISCOVERY-CODE": true, "SKIL-PERSISTENCE-STARTUP": true,
	"SKIL-MEMORY-SATURATION": true, "SKIL-MP-001": true,
	"SKIL-DEP-001": true, "SKIL-DEP-002": true, "SKIL-DEP-VULN": true, "SKIL-DEP-ABANDONED": true,
	"SKIL-CONTAINER-TRUST": true, "SKIL-TRANSPORT-INSECURE": true,
	"SKIL-IAC-WILDCARD-POLICY": true, "SKIL-IAC-OPEN-CIDR": true,
	"SKIL-ABUSE-PHYSICAL-HARM": true, "SKIL-ABUSE-MALWARE": true, "SKIL-ABUSE-PHISHING": true,
	"SKIL-ABUSE-DESTRUCTION": true, "SKIL-ABUSE-EVASION": true, "SKIL-ABUSE-EXHAUSTION": true,
	"SKIL-YARA-*": true, "SKIL-SEM-SECURITY": true, "SKIL-SEM-COMPOSITE": true,
	"SKIL-CAP-DECLARATION-MISSING": true, "SKIL-MANIFEST-PERMISSION-STAGING": true,
	"SKIL-MANIFEST-UNPINNED-VERSION": true, "SKIL-TA-001": true,
	"SKIL-RESOURCE-UNLIMITED": true, "SKIL-RESOURCE-TIMEOUT": true,
	"SKIL-TRIGGER-LOCK-DIFF": true,
	"SKIL-INTENT-DESCRIPTION": true, "SKIL-INTENT-CONTEXT": true,
	"SKIL-INTENT-SCOPE": true, "SKIL-INTENT-IMPLEMENTATION": true,
	"SKIL-YARA-001": true, "SKIL-YARA-002": true, "SKIL-YARA-003": true, "SKIL-YARA-004": true,
}

func TestPropertySKILRulesExist(t *testing.T) {
	m := readProperties(t)
	for _, p := range m.Properties {
		for _, ruleID := range p.SKILRules {
			if !knownRules[ruleID] {
				t.Errorf("property %q references unknown rule %q — update knownRules or fix the YAML", p.ID, ruleID)
			}
		}
	}
}

func TestPropertyFixturesExist(t *testing.T) {
	m := readProperties(t)
	for _, p := range m.Properties {
		pos := filepath.Join("fixtures", p.Fixture, "positive")
		neg := filepath.Join("fixtures", p.Fixture, "negative")
		if _, err := os.Stat(pos); os.IsNotExist(err) {
			t.Errorf("property %q missing positive fixture dir: %s", p.ID, pos)
		}
		if _, err := os.Stat(neg); os.IsNotExist(err) {
			t.Errorf("property %q missing negative fixture dir: %s", p.ID, neg)
		}
	}
}

func TestNoMISSINGInParityDoc(t *testing.T) {
	data, err := os.ReadFile("../../docs/external-scanner-feature-parity.md")
	if err != nil {
		t.Fatal(err)
	}

	knownDesignGaps := map[string]bool{
		"SQP-3 — Natural-language policy violations": true, // inherently LLM-judgment property
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
		allowed := false
		for gap := range knownDesignGaps {
			if strings.Contains(line, gap) {
				allowed = true
				break
			}
		}
		if !allowed {
			t.Errorf("unexpected MISSING entry in property table: %s", trimmed)
		}
	}
}

func TestPropertyStatusNotUNMAPPED(t *testing.T) {
	m := readProperties(t)
	for _, p := range m.Properties {
		if p.Status == "" {
			t.Errorf("property %q has empty status — set to FULL, PARTIAL, or MISSING_BY_DESIGN", p.ID)
		}
		if p.Status == "UNMAPPED" {
			t.Errorf("property %q status is UNMAPPED — set to FULL or PARTIAL if coverage exists", p.ID)
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

func generateCrosswalkTable(properties []Property) string {
	// Sort by external_rule for deterministic output
	type entry struct{ ext, behavior, natives, status, analyzer, notes string }
	var entries []entry
	for _, p := range properties {
		ext := p.ExternalRule
		behavior := p.Description
		natives := ""
		for i, r := range p.SKILRules {
			if i > 0 {
				natives += ", "
			}
			natives += r
		}
		status := p.Status
		a := analyzerLabel(p)
		entries = append(entries, entry{ext, behavior, "`" + natives + "`", status, a, p.Notes})
	}
	// Sort by external_rule
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].ext > entries[j].ext {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	var b strings.Builder
	b.WriteString("## Auto-generated (properties.yaml)\n\n")
	b.WriteString("| External ID | Reference behavior | Native equivalent | Coverage | Analyzer | Notes |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", e.ext, e.behavior, e.natives, e.status, e.analyzer, e.notes)
	}
	return b.String()
}

func analyzerLabel(p Property) string {
	rules := p.SKILRules
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
