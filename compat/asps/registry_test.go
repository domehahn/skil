package asps

import "testing"

func TestLoadReturnsEmbeddedRegistry(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if reg.SchemaVersion != "1.0.0" {
		t.Fatalf("schema_version = %q, want 1.0.0", reg.SchemaVersion)
	}
	if len(reg.Properties) != 120 {
		t.Fatalf("expected 120 properties, got %d", len(reg.Properties))
	}
	if len(reg.Domains) != 15 {
		t.Fatalf("expected 15 domains, got %d", len(reg.Domains))
	}
	found := false
	for _, p := range reg.Properties {
		if p.ID == "ASP-08.03" {
			found = true
			if p.SKILStatus != "PARTIAL" || len(p.SKILControls) != 1 || p.SKILControls[0] != "SKIL-A2A-002" {
				t.Fatalf("unexpected ASP-08.03 property: %#v", p)
			}
		}
	}
	if !found {
		t.Fatal("expected to find property ASP-08.03")
	}
}
