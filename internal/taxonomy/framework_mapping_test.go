package taxonomy

import "testing"

func TestEveryTaxonomyDomainHasExternalFrameworkCrosswalk(t *testing.T) {
	reg := NewRegistry()
	for _, dom := range reg.Domains() {
		cw, ok := reg.CrosswalkForDomain(dom.ID)
		if !ok {
			t.Fatalf("domain %q is missing an ExternalFrameworkMapping", dom.ID)
		}
		if len(cw.OWASPLLM) == 0 || len(cw.OWASPAgentic) == 0 || len(cw.MITREATLAS) == 0 || len(cw.NISTAIRMF) == 0 || len(cw.CWE) == 0 {
			t.Fatalf("domain %q has incomplete framework crosswalk: %+v", dom.ID, cw)
		}
	}
	d1 := reg.TaxonomyDigest()
	d2 := reg.TaxonomyDigest()
	if d1 == "" || d1 != d2 {
		t.Fatalf("expected deterministic non-empty taxonomy digest, got %q vs %q", d1, d2)
	}
}
