package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

func Create(scan skil.ScanResult) skil.Attestation {
	analysis := []string{}
	for name, state := range scan.Coverage {
		if state == skil.CoverageCompleted {
			analysis = append(analysis, name)
		}
	}
	sort.Strings(analysis)
	var refSummary *skil.ReferenceClosureSummary
	if scan.Closure != nil {
		refSummary = &skil.ReferenceClosureSummary{
			RootDigest: scan.Closure.RootDigest, Digest: scan.Closure.Digest,
			Nodes: len(scan.Closure.Nodes), RequiredNodes: scan.Closure.RequiredNodes,
			UnresolvedNodes: scan.Closure.UnresolvedNodes, BlockingFindings: scan.Closure.BlockingFindings,
			MaxDepth: scan.Closure.MaxDepth, Complete: scan.Closure.Complete,
			Verified: scan.Closure.Verified, State: scan.Closure.State,
		}
	}
	e := skil.Evidence{Type: "security-scan", Producer: "skil", ProducerVer: skil.Version,
		SubjectDigest: scan.Artifact.SubjectDigest(), Timestamp: time.Now().UTC(), PayloadDigest: FindingsDigest(scan.Findings),
		Result:     skil.EvidenceResult{Status: scan.Status, Verdict: scan.Verdict, MaximumSeverity: scan.Maximum, RiskScore: scan.RiskScore, Findings: len(scan.Findings)},
		Inspection: &scan.Completeness, InspectionDigest: InspectionDigest(scan.Inspection),
		ObservationDigest: ObservationsDigest(scan.Observations),
		ReferenceClosure:  refSummary}
	return skil.Attestation{
		Version: 1, Subject: skil.Subject{Name: scan.Artifact.Name, Version: scan.Artifact.Version, SHA256: scan.Artifact.SubjectDigest()},
		Producer: skil.Producer{Name: "skil", Version: skil.Version}, Analysis: analysis,
		Result:    skil.AttestResult{Status: scan.Status, Verdict: scan.Verdict, MaximumSeverity: scan.Maximum, RiskScore: scan.RiskScore},
		Timestamp: time.Now().UTC(), Evidence: []skil.Evidence{e},
		ReferenceClosure: refSummary, Closure: scan.Closure,
	}
}

func InspectionDigest(items []skil.InspectionWorkItem) string {
	payload, _ := json.Marshal(items)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func FindingsDigest(findings []skil.Finding) string {
	payload, _ := json.Marshal(findings)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func ObservationsDigest(observations []skil.CapabilityObservation) string {
	payload, _ := json.Marshal(observations)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func EvalDigest(result skil.EvalResult) string {
	payload, _ := json.Marshal(result)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func AttachEval(attestation *skil.Attestation, result skil.EvalResult, artifact skil.Artifact) error {
	if attestation == nil {
		return fmt.Errorf("attestation is required")
	}
	if result.ArtifactDigest != artifact.SubjectDigest() || attestation.Subject.SHA256 != artifact.SubjectDigest() {
		return fmt.Errorf("evaluation result subject does not match attested artifact")
	}
	violations, denied, sideEffects := 0, 0, 0
	for _, run := range result.Runs {
		violations += len(run.Trace.ContainmentViolations)
		for _, violation := range run.Trace.ContainmentViolations {
			if violation.Denied {
				denied++
			}
			if violation.SideEffect {
				sideEffects++
			}
		}
	}
	kind := "behavioral-eval"
	if result.Coverage.Containment == skil.CoverageCompleted {
		kind = "containment-eval"
	}
	attestation.Evidence = append(attestation.Evidence, skil.Evidence{
		Type: kind, Producer: "skil", ProducerVer: skil.Version,
		SubjectDigest: artifact.SubjectDigest(), Timestamp: time.Now().UTC(),
		PayloadDigest: EvalDigest(result),
		Result:        skil.EvidenceResult{Status: result.Status, MaximumSeverity: skil.SeverityInfo},
		Evaluation: &skil.EvalEvidence{
			EvalSpecDigest: result.EvalSpecDigest, Runtime: result.Runtime, Coverage: result.Coverage,
			Metrics: result.Metrics, Violations: violations, Denied: denied, SideEffects: sideEffects,
		},
	})
	attestation.Analysis = append(attestation.Analysis, "behavioral")
	if result.Coverage.Containment == skil.CoverageCompleted {
		attestation.Analysis = append(attestation.Analysis, "containment")
	}
	sort.Strings(attestation.Analysis)
	if result.Status == skil.StatusFail {
		attestation.Result.Status = skil.StatusFail
		attestation.Result.Verdict = skil.VerdictBlock
	}
	return nil
}

func Bind(a skil.Attestation, artifact skil.Artifact) error {
	if a.Subject.SHA256 != artifact.SubjectDigest() {
		return fmt.Errorf("digest mismatch: attestation=%s artifact=%s", a.Subject.SHA256, artifact.SubjectDigest())
	}
	for _, item := range a.Evidence {
		if item.SubjectDigest != artifact.SubjectDigest() {
			return fmt.Errorf("evidence digest mismatch")
		}
	}
	return nil
}
