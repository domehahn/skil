// Package compose analyzes a collection of already-scanned skills together,
// looking for capability combinations that are only a risk in composition —
// no single skill's own scan result shows anything wrong, because no single
// skill combines, on its own, the capabilities that matter. Individually
// reviewed and approved skills can still add up to a toxic flow once they
// share a concrete resource: a skill that can read secrets/credentials and
// a skill that can reach the network are each unremarkable on their own,
// but a shared file, cache entry, or other resource one writes and the
// other reads links them into exactly the flow neither one shows alone.
//
// This deliberately does not build a general-purpose taint/data-flow graph
// across skills — that would require tracking exact data values through
// unrelated processes, which skil cannot observe from static analysis of
// independently packaged artifacts. What it does instead is correlate the
// CapabilityObservations each skill's own scan already recorded (see
// pkg/skil.CapabilityObservation and internal/analyzer's ObservationAnalyzer)
// by the concrete resource value they share — a narrower, high-signal claim
// that needs no new analysis machinery, only cross-referencing analysis
// output that already exists.
package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

// RuleToxicFlow is the one composite rule this package emits in v1. It is
// listed in internal/analyzer's native rule catalog (Analysis: "compose")
// for discoverability via `skil rules list`, even though its enforcement
// path is Analyze below rather than the single-artifact registry.Scan
// pipeline every other native rule runs through.
const RuleToxicFlow = "SKIL-COMPOSE-TOXIC-FLOW"

// credentialCapabilities are CapabilityObservation.Capability values that
// indicate a skill can read a secret, credential, or other sensitive
// environment/config data — see internal/analyzer/python_ast.go's observe
// calls and internal/analyzer/registry.go's capabilityForRule for the
// vocabulary these strings are drawn from.
var credentialCapabilities = map[string]bool{
	"secrets.read":     true,
	"environment.read": true,
}

// CompositeFinding is a finding that spans two (or more) skills — unlike
// skil.Finding, which is always located within one artifact's files, a
// CompositeFinding's evidence is the pairing itself: two skills and the
// resource that links them.
type CompositeFinding struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"rule_id"`
	Severity    skil.Severity  `json:"severity"`
	Title       string         `json:"title"`
	Message     string         `json:"message"`
	Skills      []string       `json:"skills"`
	Resource    string         `json:"resource"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Fingerprint string         `json:"fingerprint"`
}

// Result is compose's top-level output, the cross-skill analogue of
// skil.ScanResult.
type Result struct {
	SchemaVersion string             `json:"schema_version"`
	Source        string             `json:"source"`
	Skills        []string           `json:"skills"`
	Findings      []CompositeFinding `json:"findings"`
	GeneratedAt   time.Time          `json:"generated_at"`
}

// Analyze correlates the CapabilityObservations of already-scanned skills
// and returns every SKIL-COMPOSE-TOXIC-FLOW composite finding: a skill A
// with a credential/secret-read capability that writes to some concrete
// resource, and a different skill B that reads that same resource and has
// a network.outbound capability. scans with fewer than two elements never
// produce a finding — composition requires at least two skills to compose.
func Analyze(source string, scans []skil.ScanResult) Result {
	result := Result{SchemaVersion: "1.0.0", Source: source, Findings: []CompositeFinding{}, GeneratedAt: time.Now().UTC()}
	for _, scan := range scans {
		result.Skills = append(result.Skills, scan.Artifact.Name)
	}
	if len(scans) < 2 {
		return result
	}

	hasCredentialAccess := make([]bool, len(scans))
	hasNetworkEgress := make([]bool, len(scans))
	writes := map[string][]int{} // resource value -> indices of skills observed writing it
	reads := map[string][]int{}  // resource value -> indices of skills observed reading it
	for i, scan := range scans {
		for _, obs := range scan.Observations {
			switch {
			case credentialCapabilities[obs.Capability]:
				hasCredentialAccess[i] = true
			case obs.Capability == "network.outbound":
				hasNetworkEgress[i] = true
			case obs.Capability == "filesystem.write" && obs.Value != "":
				writes[obs.Value] = appendUnique(writes[obs.Value], i)
			case obs.Capability == "filesystem.read" && obs.Value != "":
				reads[obs.Value] = appendUnique(reads[obs.Value], i)
			}
		}
	}

	for resource, writerIndices := range writes {
		readerIndices, hasReaders := reads[resource]
		if !hasReaders {
			continue
		}
		for _, w := range writerIndices {
			if !hasCredentialAccess[w] {
				continue
			}
			for _, r := range readerIndices {
				if r == w || !hasNetworkEgress[r] {
					continue
				}
				result.Findings = append(result.Findings, toxicFlowFinding(scans[w].Artifact.Name, scans[r].Artifact.Name, resource))
			}
		}
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Skills[0] != b.Skills[0] {
			return a.Skills[0] < b.Skills[0]
		}
		if a.Skills[1] != b.Skills[1] {
			return a.Skills[1] < b.Skills[1]
		}
		return a.Resource < b.Resource
	})
	return result
}

func toxicFlowFinding(writer, reader, resource string) CompositeFinding {
	fp := fingerprint(RuleToxicFlow, writer, reader, resource)
	return CompositeFinding{
		ID: "C-" + strings.ToUpper(fp[:12]), RuleID: RuleToxicFlow, Severity: skil.SeverityCritical,
		Title: "Cross-skill secret-to-network flow via a shared resource",
		Message: fmt.Sprintf(
			"%q can access secrets or credentials and writes %q; %q reads %q and can reach the network. "+
				"Neither skill shows this risk on its own — a credential could flow from %q through the "+
				"shared resource to %q's network egress.",
			writer, resource, reader, resource, writer, reader),
		Skills: []string{writer, reader}, Resource: resource,
		Evidence:    map[string]any{"writer": writer, "reader": reader, "resource": resource},
		Fingerprint: fp,
	}
}

func appendUnique(indices []int, i int) []int {
	for _, existing := range indices {
		if existing == i {
			return indices
		}
	}
	return append(indices, i)
}

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}
