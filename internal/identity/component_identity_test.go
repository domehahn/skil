package identity

import "testing"

func TestConstraintClassificationAndMutableDrift(t *testing.T) {
	cases := map[string]ConstraintKind{
		"1.4.7": ConstraintExact, "^1.4.0": ConstraintRange,
		"1.x": ConstraintFloating, "latest": ConstraintLatest,
		"*": ConstraintWildcard, "main": ConstraintFloating,
		"next": ConstraintUnknown, "": ConstraintUnspecified,
	}
	for input, want := range cases {
		if got := ClassifyConstraint(input); got != want {
			t.Errorf("%q: got %s want %s", input, got, want)
		}
	}
	before := ComponentIdentity{Ecosystem: "npm", Name: "pkg", Constraint: "*", ResolvedVersion: "1.4.2", ResolvedDigest: "sha256:abc"}
	after := before
	after.ResolvedVersion = "1.4.3"
	after.ResolvedDigest = "sha256:def"
	if drift := CompareComponents(before, after); drift == nil || drift.Kind != "MUTABLE_COMPONENT_DRIFT" {
		t.Fatalf("expected drift, got %#v", drift)
	}
}

func TestExactKnownIdentityStopsSimilarity(t *testing.T) {
	known := []string{"safe-package", "safe_packages"}
	if SimilarityEligible("safe-package", known) {
		t.Fatal("exact known identity was eligible for typosquat classification")
	}
	if !SimilarityEligible("safe-packag3", known) {
		t.Fatal("unknown identity should be eligible for similarity analysis")
	}
}
