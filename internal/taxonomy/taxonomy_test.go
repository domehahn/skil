package taxonomy

import (
	"testing"
)

func TestAllDomainsHaveUniqueIDs(t *testing.T) {
	seen := map[DomainID]bool{}
	for _, d := range allDomains() {
		if seen[d.ID] {
			t.Errorf("duplicate domain ID: %s", d.ID)
		}
		seen[d.ID] = true
	}
}

func TestAllControlsHaveUniqueIDs(t *testing.T) {
	seen := map[ControlID]bool{}
	for _, c := range allControls() {
		if seen[c.ID] {
			t.Errorf("duplicate control ID: %s", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestAllControlsMapToExistingDomains(t *testing.T) {
	domains := map[DomainID]bool{}
	for _, d := range allDomains() {
		domains[d.ID] = true
	}
	for _, c := range allControls() {
		if !domains[c.Domain] {
			t.Errorf("control %s maps to unknown domain %s", c.ID, c.Domain)
		}
	}
}

func TestRegistryRoundTrip(t *testing.T) {
	r := NewRegistry()
	if len(r.Domains()) != 17 {
		t.Fatalf("expected 17 domains, got %d", len(r.Domains()))
	}
	controls := r.Controls()
	if len(controls) == 0 {
		t.Fatal("expected controls")
	}
	byDomain := r.ControlsByDomain(InstructionSecurity)
	if len(byDomain) == 0 {
		t.Fatal("expected controls in instruction security domain")
	}
}

func TestControlByRuleLookup(t *testing.T) {
	r := NewRegistry()
	c, ok := r.ControlByRule("SKIL-PI-001")
	if !ok {
		t.Fatal("expected SKIL-PI-001 to map to a control")
	}
	if c.ID != "INSTR-001" {
		t.Fatalf("expected INSTR-001, got %s", c.ID)
	}
	d, err := r.DomainByID(c.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != InstructionSecurity {
		t.Fatalf("expected instruction security domain, got %s", d.ID)
	}
}

func TestResolveSKILRule(t *testing.T) {
	r := NewRegistry()
	d, c, err := r.ResolveSKILRule("SKIL-MCP-001")
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != MCPSecurity {
		t.Fatalf("expected MCP domain, got %s", d.ID)
	}
	if c.ID != "MCP-001" {
		t.Fatalf("expected MCP-001, got %s", c.ID)
	}
}

func TestAllSKILRules(t *testing.T) {
	r := NewRegistry()
	rules := r.AllSKILRules()
	if len(rules) == 0 {
		t.Fatal("expected at least one SKIL rule in taxonomy")
	}
	prev := ""
	for _, rule := range rules {
		if rule <= prev {
			t.Fatalf("rules not sorted: %s <= %s", rule, prev)
		}
		prev = rule
	}
}

func TestValidateSKILRule(t *testing.T) {
	r := NewRegistry()
	if err := r.ValidateSKILRule("SKIL-PI-001"); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateSKILRule("NONEXISTENT-RULE"); err == nil {
		t.Fatal("expected error for unknown rule")
	}
}

func TestDomainByIDError(t *testing.T) {
	r := NewRegistry()
	_, err := r.DomainByID("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown domain")
	}
}

func TestControlByIDLookup(t *testing.T) {
	r := NewRegistry()
	c, ok := r.ControlByID("MCP-001")
	if !ok {
		t.Fatal("expected MCP-001 control")
	}
	if c.SKILRule != "SKIL-MCP-001" {
		t.Fatalf("expected SKIL-MCP-001, got %s", c.SKILRule)
	}
}

func TestControlByIDNotFound(t *testing.T) {
	r := NewRegistry()
	_, ok := r.ControlByID("NONEXISTENT")
	if ok {
		t.Fatal("expected not found")
	}
}
