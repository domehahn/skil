package skil

import "testing"

func TestControlProofRejectsEmptyExecutionEvidence(t *testing.T) {
	p := ControlProof{ControlID: "control", Analyzer: "analyzer", SubjectDigest: "sha256:subject", Required: true, RequiredStages: DefaultAssuranceStages}
	if err := p.Validate(); err == nil {
		t.Fatal("empty proof was accepted")
	}
	for _, stage := range DefaultAssuranceStages {
		p.Evidence = append(p.Evidence, AssuranceEvidence{Stage: stage, EvidenceID: string(stage), Digest: "sha256:e"})
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("complete proof rejected: %v", err)
	}
}

func TestDestinationBindingRejectsRedirectAndPathChange(t *testing.T) {
	b := VerificationDestinationBinding{
		AuthorizedProvider: "private", EffectiveProvider: "private",
		AuthorizedEndpoint: "https://verify.example/v1/check", EffectiveEndpoint: "https://verify.example/v1/other",
		CredentialScope: "scope:verify", ModelIdentity: "model",
		RequestConfigDigest: "sha256:req", EvidenceProjectionDigest: "sha256:projection",
	}
	if err := b.Validate(); err == nil {
		t.Fatal("endpoint path change was accepted")
	}
	b.EffectiveEndpoint = b.AuthorizedEndpoint
	b.Redirected = true
	if err := b.Validate(); err == nil {
		t.Fatal("redirected request was accepted")
	}
}

func TestCoverageUniverseDoesNotTreatOmittedAsComplete(t *testing.T) {
	u := CoverageUniverse{Subjects: []CoverageSubject{{ID: "a", Disposition: CoverageDiscovered, Required: true}, {ID: "b", Disposition: CoverageOmitted, Required: true}}}
	if u.Complete() {
		t.Fatal("omitted required subject produced complete coverage")
	}
	u.Subjects[1].Disposition = CoverageExcludedByPolicy
	if !u.Complete() {
		t.Fatal("authorized policy exclusion prevented closure")
	}
}

func TestFindingOccurrenceFingerprintBindsSubjectAndArtifact(t *testing.T) {
	a := NewFindingOccurrenceIdentity("RULE", "class", "subject-a", "SKILL.md", 4, 4, "artifact-a")
	b := NewFindingOccurrenceIdentity("RULE", "class", "subject-b", "SKILL.md", 4, 4, "artifact-a")
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("occurrences from different subjects collided")
	}
}

func TestOutcomeProofRequiresSemanticEvidence(t *testing.T) {
	p := AssuranceOutcomeProof{Outcome: OutcomeNotApplicable, Evidence: []string{"sha256:work"}}
	if err := p.Validate(); err == nil {
		t.Fatal("not-applicable without applicability proof was accepted")
	}
	p.ApplicabilityEvidence = "predicate:false"
	if err := p.Validate(); err != nil {
		t.Fatalf("valid not-applicable proof rejected: %v", err)
	}
}
