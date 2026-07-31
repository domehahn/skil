// Package asps provides conformance tests for the Agent Skill Security
// Properties Specification (ASPS) machine-readable registry.
package asps

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const registryPath = "asps-registry.json"
const schemaPath = "asps-schema.json"
const crosswalkPath = "asps-crosswalk.csv"

type domain struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	OWASPAgentic []string `json:"owasp_agentic"`
	OWASPLLM     []string `json:"owasp_llm"`
	MITRE        []string `json:"mitre"`
}

type securityProperty struct {
	ID              string   `json:"id"`
	DomainID        string   `json:"domain_id"`
	Domain          string   `json:"domain"`
	Name            string   `json:"name"`
	Invariant       string   `json:"invariant"`
	Detection       string   `json:"detection"`
	MinimumEvidence string   `json:"minimum_evidence"`
	OWASPAgentic    []string `json:"owasp_agentic"`
	OWASPLLM        []string `json:"owasp_llm"`
	MITREATLAS      []string `json:"mitre_atlas"`
	SKILControls    []string `json:"skil_controls"`
	SKILStatus      string   `json:"skil_status"`
}

type legacyMigration struct {
	LegacyName     string `json:"legacy_name"`
	Target         string `json:"target"`
	Classification string `json:"classification"`
}

type registry struct {
	SchemaVersion          string             `json:"schema_version"`
	Specification          string             `json:"specification"`
	Acronym                string             `json:"acronym"`
	Status                 string             `json:"status"`
	Snapshot               string             `json:"snapshot"`
	PropertyCount          int                `json:"property_count"`
	DomainCount            int                `json:"domain_count"`
	Domains                []domain           `json:"domains"`
	Properties             []securityProperty `json:"properties"`
	LegacyCatalogMigration []legacyMigration  `json:"legacy_catalog_migration"`
}

var propertyIDPattern = regexp.MustCompile(`^ASP-[0-9]{2}\.[0-9]{2}$`)
var domainIDPattern = regexp.MustCompile(`^ASP-[0-9]{2}$`)
var snapshotPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

var knownSKILStatus = map[string]bool{
	"IMPLEMENTED": true, "PARTIAL": true, "NEW": true, "PROVIDER_BACKED": true,
}

var knownOWASPAgentic = map[string]bool{
	"ASI01": true, "ASI02": true, "ASI03": true, "ASI04": true, "ASI05": true,
	"ASI06": true, "ASI07": true, "ASI08": true, "ASI09": true, "ASI10": true,
}

var knownOWASPLLM = map[string]bool{
	"LLM01": true, "LLM02": true, "LLM03": true, "LLM04": true, "LLM05": true,
	"LLM06": true, "LLM07": true, "LLM08": true, "LLM09": true, "LLM10": true,
}

var knownClassifications = map[string]bool{
	"PROPERTY": true, "SUBPROPERTY": true, "PROPERTY_COMPOSITION": true,
	"PROPERTY_SPLIT": true, "MECHANISM": true, "MECHANISM_FAMILY": true,
	"EVIDENCE_SOURCE": true,
}

func readRegistry(t *testing.T) registry {
	t.Helper()
	data, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	var reg registry
	if err := json.Unmarshal(data, &reg); err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestRegistryValidatesAgainstSchema(t *testing.T) {
	regData, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	var regValue any
	if err := json.Unmarshal(regData, &regValue); err != nil {
		t.Fatal(err)
	}
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var schemaValue any
	if err := json.Unmarshal(schemaData, &schemaValue); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("asps-schema.json", schemaValue); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("asps-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(regValue); err != nil {
		t.Errorf("asps-registry.json does not conform to asps-schema.json: %v", err)
	}
}

func TestRegistryCountsAndIdentity(t *testing.T) {
	reg := readRegistry(t)
	if reg.SchemaVersion != "1.0.0" {
		t.Errorf("schema_version = %q, want 1.0.0", reg.SchemaVersion)
	}
	if reg.Specification != "Agent Skill Security Properties Specification" {
		t.Errorf("specification = %q", reg.Specification)
	}
	if reg.Acronym != "ASPS" {
		t.Errorf("acronym = %q, want ASPS", reg.Acronym)
	}
	if reg.Status != "proposed" {
		t.Errorf("status = %q, want proposed", reg.Status)
	}
	if !snapshotPattern.MatchString(reg.Snapshot) {
		t.Errorf("snapshot = %q, want YYYY-MM-DD", reg.Snapshot)
	}
	if len(reg.Domains) != 15 {
		t.Errorf("domains = %d, want 15", len(reg.Domains))
	}
	if len(reg.Properties) != 120 {
		t.Errorf("properties = %d, want 120", len(reg.Properties))
	}
	if reg.PropertyCount != len(reg.Properties) {
		t.Errorf("property_count = %d does not match actual %d", reg.PropertyCount, len(reg.Properties))
	}
	if reg.DomainCount != len(reg.Domains) {
		t.Errorf("domain_count = %d does not match actual %d", reg.DomainCount, len(reg.Domains))
	}
}

func TestDomainStructure(t *testing.T) {
	reg := readRegistry(t)
	seen := map[string]bool{}
	for _, dom := range reg.Domains {
		if !domainIDPattern.MatchString(dom.ID) {
			t.Errorf("domain id %q does not match ASP-XX", dom.ID)
		}
		if seen[dom.ID] {
			t.Errorf("duplicate domain id %q", dom.ID)
		}
		seen[dom.ID] = true
		if dom.Name == "" {
			t.Errorf("domain %s has empty name", dom.ID)
		}
		if len(dom.OWASPAgentic) == 0 {
			t.Errorf("domain %s has no OWASP Agentic mapping", dom.ID)
		}
		if len(dom.OWASPLLM) == 0 {
			t.Errorf("domain %s has no OWASP LLM mapping", dom.ID)
		}
		if len(dom.MITRE) == 0 {
			// ASP-14 (Auditability, Observability & Accountability) intentionally
			// has no direct MITRE ATLAS technique mapping.
			if dom.ID != "ASP-14" {
				t.Errorf("domain %s has no MITRE ATLAS mapping", dom.ID)
			}
		}
		for _, id := range dom.OWASPAgentic {
			if !knownOWASPAgentic[id] {
				t.Errorf("domain %s references unknown OWASP Agentic %q", dom.ID, id)
			}
		}
		for _, id := range dom.OWASPLLM {
			if !knownOWASPLLM[id] {
				t.Errorf("domain %s references unknown OWASP LLM %q", dom.ID, id)
			}
		}
	}
}

func TestPropertyStructure(t *testing.T) {
	reg := readRegistry(t)
	domains := map[string]string{}
	for _, dom := range reg.Domains {
		domains[dom.ID] = dom.Name
	}
	perDomain := map[string]int{}
	seen := map[string]bool{}
	prevDomain := ""
	for _, p := range reg.Properties {
		if !propertyIDPattern.MatchString(p.ID) {
			t.Errorf("property id %q does not match ASP-XX.YY", p.ID)
		}
		if seen[p.ID] {
			t.Errorf("duplicate property id %q", p.ID)
		}
		seen[p.ID] = true
		if !domainIDPattern.MatchString(p.DomainID) {
			t.Errorf("property %s has malformed domain_id %q", p.ID, p.DomainID)
		}
		if _, ok := domains[p.DomainID]; !ok {
			t.Errorf("property %s references unknown domain_id %q", p.ID, p.DomainID)
		}
		if p.Domain != domains[p.DomainID] {
			t.Errorf("property %s domain %q does not match domain_id name %q", p.ID, p.Domain, domains[p.DomainID])
		}
		if !strings.HasPrefix(p.ID, p.DomainID+".") {
			t.Errorf("property %s id does not start with its domain_id %s", p.ID, p.DomainID)
		}
		perDomain[p.DomainID]++
		if p.Name == "" || p.Invariant == "" || p.Detection == "" || p.MinimumEvidence == "" {
			t.Errorf("property %s has an empty required text field", p.ID)
		}
		if !knownSKILStatus[p.SKILStatus] {
			t.Errorf("property %s has invalid skil_status %q", p.ID, p.SKILStatus)
		}
		if len(p.OWASPAgentic) == 0 {
			t.Errorf("property %s has no OWASP Agentic mapping", p.ID)
		}
		for _, id := range p.OWASPAgentic {
			if !knownOWASPAgentic[id] {
				t.Errorf("property %s references unknown OWASP Agentic %q", p.ID, id)
			}
		}
		for _, id := range p.OWASPLLM {
			if !knownOWASPLLM[id] {
				t.Errorf("property %s references unknown OWASP LLM %q", p.ID, id)
			}
		}
		// properties must be globally ordered by domain block then index
		cur := p.DomainID
		if prevDomain != "" && cur < prevDomain {
			t.Errorf("properties out of order: %s appears before %s", cur, prevDomain)
		}
		prevDomain = cur
	}
	for domID, name := range domains {
		if perDomain[domID] != 8 {
			t.Errorf("domain %s (%s) has %d properties, want 8", domID, name, perDomain[domID])
		}
	}
}

func TestRegistryHasNoProhibitedBranding(t *testing.T) {
	data, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(data))
	for _, forbidden := range []string{"skill" + "spector", "68 " + "patterns", "17 " + "categories"} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("%s contains prohibited third-party compatibility branding %q", registryPath, forbidden)
		}
	}
}

func TestLegacyMigrationTargetsExist(t *testing.T) {
	reg := readRegistry(t)
	valid := map[string]bool{}
	for _, p := range reg.Properties {
		valid[p.ID] = true
	}
	for _, m := range reg.LegacyCatalogMigration {
		// A legacy migration may target several ASP properties (e.g. when one
		// legacy catalog entry splits into multiple properties).
		for _, target := range strings.Split(m.Target, "/") {
			if !valid[target] {
				t.Errorf("legacy migration %q targets unknown property %s", m.LegacyName, target)
			}
		}
		if !knownClassifications[m.Classification] {
			t.Errorf("legacy migration %q has unknown classification %q", m.LegacyName, m.Classification)
		}
		if m.LegacyName == "" {
			t.Errorf("legacy migration with empty name targets %s", m.Target)
		}
	}
}

func TestCrosswalkMatchesRegistry(t *testing.T) {
	reg := readRegistry(t)
	byID := map[string]securityProperty{}
	for _, p := range reg.Properties {
		byID[p.ID] = p
	}

	f, err := os.Open(crosswalkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 121 { // header + 120 properties
		t.Fatalf("crosswalk has %d rows, want 121 (header + 120)", len(rows))
	}
	header := rows[0]
	wantHeader := []string{"property_id", "domain", "name", "owasp_agentic", "owasp_llm", "mitre_atlas", "skil_controls", "skil_status"}
	if !slices.Equal(header, wantHeader) {
		t.Fatalf("crosswalk header %v, want %v", header, wantHeader)
	}

	seen := map[string]bool{}
	for _, row := range rows[1:] {
		id := row[0]
		if len(row) != 8 {
			t.Errorf("crosswalk row %q has %d columns, want 8", id, len(row))
			continue
		}
		if seen[id] {
			t.Errorf("duplicate crosswalk property %q", id)
		}
		seen[id] = true
		p, ok := byID[id]
		if !ok {
			t.Errorf("crosswalk references unknown property %q", id)
			continue
		}
		if row[1] != p.Domain {
			t.Errorf("crosswalk domain for %s = %q, want %q", id, row[1], p.Domain)
		}
		if row[2] != p.Name {
			t.Errorf("crosswalk name for %s = %q, want %q", id, row[2], p.Name)
		}
		if row[7] != p.SKILStatus {
			t.Errorf("crosswalk skil_status for %s = %q, want %q", id, row[7], p.SKILStatus)
		}
		if !slices.Equal(splitSemicolon(row[3]), p.OWASPAgentic) {
			t.Errorf("crosswalk owasp_agentic for %s = %q, want %v", id, row[3], p.OWASPAgentic)
		}
		if !slices.Equal(splitSemicolon(row[4]), p.OWASPLLM) {
			t.Errorf("crosswalk owasp_llm for %s = %q, want %v", id, row[4], p.OWASPLLM)
		}
		if !slices.Equal(splitSemicolon(row[5]), p.MITREATLAS) {
			t.Errorf("crosswalk mitre_atlas for %s = %q, want %v", id, row[5], p.MITREATLAS)
		}
		if !slices.Equal(splitSemicolon(row[6]), p.SKILControls) {
			t.Errorf("crosswalk skil_controls for %s = %q, want %v", id, row[6], p.SKILControls)
		}
	}
}

func TestCrosswalkPathsAreConsistent(t *testing.T) {
	// The registry, schema and crosswalk must live in the same directory and be
	// readable from the package working directory (go test ./compat/asps/).
	for _, path := range []string{registryPath, schemaPath, crosswalkPath} {
		abs, err := filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(abs); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func splitSemicolon(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ";")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func Example_registry() {
	reg := readRegistryForExample()
	fmt.Printf("%s v%s: %d properties in %d domains", reg.Acronym, reg.SchemaVersion, len(reg.Properties), len(reg.Domains))
	// Output: ASPS v1.0.0: 120 properties in 15 domains
}

func readRegistryForExample() registry {
	data, err := os.ReadFile(registryPath)
	if err != nil {
		panic(err)
	}
	var reg registry
	if err := json.Unmarshal(data, &reg); err != nil {
		panic(err)
	}
	return reg
}
