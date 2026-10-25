package assurance

import (
	"fmt"
	"sort"

	"github.com/domehahn/skil/pkg/skil"
)

// AssessScan translates the existing inspection and budget ledgers into a
// conservative assurance report. It intentionally does not use finding count
// as proof of execution: an empty result and a successful zero-finding pass
// are distinguished by the work ledger.
func AssessScan(scan skil.ScanResult) *skil.AssuranceReport {
	required := []skil.AssuranceStage{
		skil.StageExpected, skil.StageScheduled, skil.StageInvocationBuilt,
		skil.StageEvidenceProduced, skil.StageEvidenceCommitted,
		skil.StageDecisionConsumed,
	}
	if scan.ProofPersisted {
		required = append(required, skil.StageProofPersisted)
	}
	controls := make([]skil.ControlProof, 0, len(scan.Inspection))
	limitations := make([]skil.AssuranceLimitation, 0)
	allComplete := len(scan.Inspection) > 0
	for _, item := range scan.Inspection {
		proof := skil.ControlProof{ControlID: item.Analyzer, Analyzer: item.Analyzer,
			SubjectDigest: scan.Artifact.SubjectDigest(), RequiredStages: required, Required: true}
		if item.Outcome == skil.InspectionCompleted {
			for _, stage := range required {
				proof.Evidence = append(proof.Evidence, skil.AssuranceEvidence{Stage: stage,
					EvidenceID: fmt.Sprintf("inspection:%s:%s:%s", item.Analyzer, item.File, stage),
					Digest:     skil.DigestJSON(item), Detail: item.File})
			}
			proof.Complete = true
		} else {
			allComplete = false
			proof.Limitation = item.Reason
			if proof.Limitation == "" {
				proof.Limitation = string(item.Outcome)
			}
			limitations = append(limitations, skil.AssuranceLimitation{
				Subject: item.File, Phase: "inspection", Cause: proof.Limitation,
				Dimensions: []skil.AssuranceDimension{skil.DimensionArtifactInspection, skil.DimensionControlExecution},
				Evidence:   []string{skil.DigestJSON(item)}, Analyzer: item.Analyzer,
				Control: item.Analyzer, DecisionEffect: "prevents COMPLETE assurance",
			})
		}
		controls = append(controls, proof)
	}
	if len(scan.Budget.Exceeded) > 0 {
		allComplete = false
		limitations = append(limitations, skil.AssuranceLimitation{
			Subject: scan.Artifact.SubjectDigest(), Phase: "budget", Cause: "analysis budget exceeded",
			Dimensions: []skil.AssuranceDimension{skil.DimensionArtifactInspection, skil.DimensionControlExecution},
			Evidence:   []string{skil.DigestJSON(scan.Budget)}, DecisionEffect: "prevents COMPLETE assurance",
		})
	}
	if !scan.ProofPersisted {
		allComplete = false
		limitations = append(limitations, skil.AssuranceLimitation{
			Subject: scan.Artifact.SubjectDigest(), Phase: "persistence", Cause: "proof has not been persisted",
			Dimensions:     []skil.AssuranceDimension{skil.DimensionEvidenceIntegrity},
			Evidence:       []string{skil.DigestJSON(scan.ProofPersisted)},
			DecisionEffect: "prevents COMPLETE assurance",
		})
	}
	if scan.Closure != nil && !scan.Closure.Complete {
		allComplete = false
		limitations = append(limitations, skil.AssuranceLimitation{
			Subject: scan.Closure.RootDigest, Phase: "reference-closure", Cause: "reference closure incomplete",
			Dimensions: []skil.AssuranceDimension{skil.DimensionReferenceResolution},
			Evidence:   []string{scan.Closure.Digest}, DecisionEffect: "prevents COMPLETE assurance",
		})
	}
	dimensions := []skil.AssuranceDimensionResult{
		{Dimension: skil.DimensionArtifactInspection, State: dimensionState(allComplete), Evidence: []string{skil.DigestJSON(scan.Inspection)}},
		{Dimension: skil.DimensionControlExecution, State: dimensionState(allComplete), Evidence: []string{skil.DigestJSON(scan.Inspection)}},
		{Dimension: skil.DimensionEvidenceIntegrity, State: dimensionState(scan.Artifact.SubjectDigest() != ""), Evidence: []string{scan.Artifact.SubjectDigest()}},
	}
	if scan.Closure != nil {
		state := skil.DimensionComplete
		if !scan.Closure.Complete {
			state = skil.DimensionPartial
		}
		dimensions = append(dimensions, skil.AssuranceDimensionResult{Dimension: skil.DimensionReferenceResolution, State: state, Evidence: []string{scan.Closure.Digest}})
	}
	sort.Slice(dimensions, func(i, j int) bool { return dimensions[i].Dimension < dimensions[j].Dimension })
	outcome := skil.OutcomePartial
	if allComplete {
		outcome = skil.OutcomeComplete
	}
	proof := skil.AssuranceOutcomeProof{Outcome: outcome, Evidence: []string{skil.DigestJSON(controls), skil.DigestJSON(dimensions)}}
	if !allComplete {
		proof.Unresolved = []string{"one or more required analysis transitions are not proven"}
	}
	report := &skil.AssuranceReport{Outcome: outcome, Controls: controls, Dimensions: dimensions, Limitations: limitations, Proof: proof}
	report.EvidenceDigest = skil.DigestJSON(struct {
		Controls    []skil.ControlProof
		Dimensions  []skil.AssuranceDimensionResult
		Limitations []skil.AssuranceLimitation
	}{controls, dimensions, limitations})
	return report
}

func dimensionState(complete bool) skil.DimensionState {
	if complete {
		return skil.DimensionComplete
	}
	return skil.DimensionPartial
}
