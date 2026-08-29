package evidence

import (
	"github.com/domehahn/skil/pkg/skil"
	"strings"
	"testing"
)

func TestEvidenceBinding(t *testing.T) {
	scan := skil.ScanResult{Artifact: skil.Artifact{Name: "a", Digest: "aaa"}, Status: skil.StatusPass,
		Verdict: skil.VerdictClear, Maximum: skil.SeverityLow,
		Inspection:   []skil.InspectionWorkItem{{Analyzer: "test", Version: "1", File: "SKILL.md", Outcome: skil.InspectionCompleted}},
		Completeness: skil.InspectionSummary{Total: 1, Applicable: 1, Completed: 1, Completeness: 1}}
	a := Create(scan)
	if a.Result.Verdict != skil.VerdictClear || a.Evidence[0].Result.Verdict != skil.VerdictClear {
		t.Fatalf("native verdict not bound into attestation: %#v", a)
	}
	if a.Evidence[0].Inspection == nil || a.Evidence[0].InspectionDigest == "" {
		t.Fatalf("inspection accounting was not bound into attestation: %#v", a.Evidence[0])
	}
	if err := Bind(a, scan.Artifact); err != nil {
		t.Fatal(err)
	}
	if err := Bind(a, skil.Artifact{Digest: "bbb"}); err == nil {
		t.Fatal("expected substitution rejection")
	}
}

func TestAttestationBindsCompleteClosureStateAndGraph(t *testing.T) {
	closure := skil.AssuranceClosure{
		RootDigest: "aaa", Digest: "sha256:" + strings.Repeat("b", 64),
		Complete: true, Verified: true, State: skil.AssuranceSafe,
		RequiredNodes: 2, Nodes: []skil.ClosureNode{{ID: "aaa"}, {ID: "helper"}},
	}
	attestation := Create(skil.ScanResult{
		Artifact: skil.Artifact{Name: "a", Digest: "aaa"}, Status: skil.StatusPass,
		Verdict: skil.VerdictClear, Maximum: skil.SeverityInfo, Closure: &closure,
	})
	if attestation.Closure == nil || attestation.ReferenceClosure == nil {
		t.Fatalf("closure graph and summary were not attested: %#v", attestation)
	}
	if attestation.ReferenceClosure.RootDigest != "aaa" || attestation.ReferenceClosure.State != skil.AssuranceSafe ||
		!attestation.ReferenceClosure.Verified || attestation.ReferenceClosure.RequiredNodes != 2 {
		t.Fatalf("closure assurance metadata was not bound: %#v", attestation.ReferenceClosure)
	}
}

func TestAttestationBindsDependencySourceIdentity(t *testing.T) {
	base := skil.DependencyIdentity{
		Ecosystem: "npm", Package: "helper", Version: "1.2.3", SourceKind: "registry",
		SourceURL: "https://registry.npmjs.org/", ManifestDigest: strings.Repeat("a", 64),
		Evidence: skil.Location{File: "package-lock.json", StartLine: 1, EndLine: 1},
	}
	scan := skil.ScanResult{Artifact: skil.Artifact{Name: "a", Digest: "aaa"}, Dependencies: []skil.DependencyIdentity{base}}
	attestation := Create(scan)
	if len(attestation.Dependencies) != 1 || attestation.Evidence[0].DependencyDigest == "" {
		t.Fatalf("dependency inventory was not bound: %#v", attestation)
	}
	changed := base
	changed.SourceURL = "https://packages.example.test/npm/"
	if DependenciesDigest([]skil.DependencyIdentity{base}) == DependenciesDigest([]skil.DependencyIdentity{changed}) {
		t.Fatal("same package/version from a different registry retained the same evidence digest")
	}
}

func TestAttachEvalBindsCoverageMetricsAndFailure(t *testing.T) {
	artifact := skil.Artifact{Name: "a", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	attestation := Create(skil.ScanResult{Artifact: artifact, Status: skil.StatusPass,
		Verdict: skil.VerdictClear, Maximum: skil.SeverityInfo})
	compliance := 0.0
	result := skil.EvalResult{
		ArtifactDigest: artifact.Digest, EvalSpecDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Runtime: "isolated-process", Status: skil.StatusFail,
		Coverage: skil.EvalCoverage{Behavioral: skil.CoverageCompleted, Containment: skil.CoverageCompleted},
		Metrics:  skil.EvalMetrics{ContainmentComplianceRate: &compliance},
		Runs: []skil.EvalRun{{Trace: skil.EvalTrace{ContainmentViolations: []skil.ContainmentViolation{{
			Category: skil.AttackContainmentEscape, Denied: true,
		}}}}},
	}
	if err := AttachEval(&attestation, result, artifact); err != nil {
		t.Fatal(err)
	}
	if attestation.Result.Status != skil.StatusFail || attestation.Result.Verdict != skil.VerdictBlock {
		t.Fatalf("failed evaluation did not fail the attestation: %#v", attestation)
	}
	item := attestation.Evidence[len(attestation.Evidence)-1]
	if item.Type != "containment-eval" || item.PayloadDigest != EvalDigest(result) ||
		item.Evaluation == nil || item.Evaluation.Violations != 1 || item.Evaluation.Denied != 1 {
		t.Fatalf("evaluation evidence is incomplete: %#v", item)
	}
	if err := AttachEval(&attestation, result, skil.Artifact{Digest: "different"}); err == nil {
		t.Fatal("evaluation substitution must be rejected")
	}
}
