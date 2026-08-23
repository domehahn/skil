// Package composeassure verifies internal/compose's static cross-skill
// toxic-flow prediction (SKIL-COMPOSE-TOXIC-FLOW) against real observed
// runtime behavior: it runs every skill in a collection's own behavioral
// eval once each against one shared scratch workspace, so a real write
// from one skill and a real read from another can land on the same
// physical path, and correlates the resulting per-skill operation traces
// into observed cross-skill flows.
//
// This is deliberately a comparison, not a replacement: a shared-workspace
// eval run only exercises whatever inputs that eval's own test scenario
// drives, so "not observed this run" is not proof a static finding is
// wrong — but an observed flow the static analysis never predicted is a
// genuine, empirically-confirmed gap the static model missed.
package composeassure

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/domehahn/skil/internal/compose"
	"github.com/domehahn/skil/pkg/skil"
)

// SkillRun is one collection member's own eval outcome, flattened to just
// the operations the correlation logic needs.
type SkillRun struct {
	Skill      string
	Path       string
	EvalPath   string
	Evaluated  bool // false when the skill had no eval to run (recorded, not fatal)
	Error      string
	Operations []skil.Operation
}

// Flow is one observed cross-skill toxic flow: WriterSkill wrote Resource,
// and ReaderSkill both read that same Resource and separately contacted
// ReaderNetworkTarget over the network — the write-then-read-then-exfil
// shape SKIL-COMPOSE-TOXIC-FLOW predicts statically, now confirmed by
// actually running both skills against a shared workspace.
type Flow struct {
	WriterSkill         string
	ReaderSkill         string
	Resource            string
	ReaderNetworkTarget string
	// CorrelationID ties this flow back to the exact writer/reader/
	// resource triple deterministically, so the same real-world flow
	// always gets the same ID across repeated runs.
	CorrelationID string
}

// Result is the full comparison: what internal/compose predicted
// statically, what was actually run, what was actually observed, and how
// the two sides line up.
type Result struct {
	Static   compose.Result
	Runs     []SkillRun
	Observed []Flow
	// Confirmed are static findings with a matching observed Flow.
	Confirmed []compose.CompositeFinding
	// StaticOnly are static findings with no matching observed Flow in
	// this run — not exercised, not necessarily wrong.
	StaticOnly []compose.CompositeFinding
	// RuntimeOnlyGaps are observed flows with no matching static finding
	// at all — a real gap in the static prediction, confirmed by
	// execution.
	RuntimeOnlyGaps []Flow
}

// Correlate builds the observed-flow graph from every skill run's
// operations: a filesystem.write by one skill, a filesystem.read of the
// exact same Target by a different skill, and that reader also having at
// least one network.outbound operation anywhere in its own trace.
func Correlate(runs []SkillRun) []Flow {
	var flows []Flow
	for _, writer := range runs {
		for _, wop := range writer.Operations {
			if wop.Capability != "filesystem.write" || wop.Target == "" {
				continue
			}
			for _, reader := range runs {
				if reader.Skill == writer.Skill {
					continue
				}
				readsResource := false
				networkTarget := ""
				for _, rop := range reader.Operations {
					if rop.Capability == "filesystem.read" && rop.Target == wop.Target {
						readsResource = true
					}
					if rop.Capability == "network.outbound" && rop.Target != "" && networkTarget == "" {
						networkTarget = rop.Target
					}
				}
				if readsResource && networkTarget != "" {
					flows = append(flows, Flow{
						WriterSkill: writer.Skill, ReaderSkill: reader.Skill, Resource: wop.Target,
						ReaderNetworkTarget: networkTarget,
						CorrelationID:       correlationID(writer.Skill, reader.Skill, wop.Target),
					})
				}
			}
		}
	}
	return flows
}

func correlationID(writer, reader, resource string) string {
	sum := sha256.Sum256([]byte(writer + "\x00" + reader + "\x00" + resource))
	return hex.EncodeToString(sum[:])[:16]
}

// Reconcile cross-references static's composite findings against the
// observed flows and returns the full Result.
func Reconcile(static compose.Result, runs []SkillRun) Result {
	observed := Correlate(runs)
	result := Result{
		Static: static, Runs: runs, Observed: observed,
		Confirmed: []compose.CompositeFinding{}, StaticOnly: []compose.CompositeFinding{}, RuntimeOnlyGaps: []Flow{},
	}
	matchedObserved := make([]bool, len(observed))
	for _, finding := range static.Findings {
		if len(finding.Skills) != 2 {
			result.StaticOnly = append(result.StaticOnly, finding)
			continue
		}
		matched := false
		for i, flow := range observed {
			if flow.WriterSkill == finding.Skills[0] && flow.ReaderSkill == finding.Skills[1] && flow.Resource == finding.Resource {
				matched = true
				matchedObserved[i] = true
			}
		}
		if matched {
			result.Confirmed = append(result.Confirmed, finding)
		} else {
			result.StaticOnly = append(result.StaticOnly, finding)
		}
	}
	for i, flow := range observed {
		if !matchedObserved[i] {
			result.RuntimeOnlyGaps = append(result.RuntimeOnlyGaps, flow)
		}
	}
	return result
}
