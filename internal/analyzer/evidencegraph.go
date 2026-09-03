package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"

	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

// Evidence Graph correlation.
//
// Deterministic Threat-Chain Correlation (chains.go) already combines
// existing rule IDs and capabilities into named, fixed multi-stage-attack
// findings, explicitly NOT as a general graph — this file builds the
// actual graph structure chains.go's own doc comment says it deliberately
// isn't: typed nodes (a Finding, a CapabilityObservation, or a synthesized
// taint source/sink endpoint) and typed edges between them, each carrying
// an explicit EvidenceState (OBSERVED/INFERRED/VERIFIED) rather than a
// single flat pass/fail per fixed chain.
//
// It still never invents a new *detection* primitive: every node and edge
// is backed by evidence an existing analyzer already produced — a taint
// finding's own recorded source/sink, or a threat-chain's own recorded
// contributing findings. The one genuinely new correlation this file adds
// is the credential-read + separate-network-operation co-occurrence edge
// below, for the case static taint tracing can't connect (cross-function
// or cross-file) — clearly INFERRED, never OBSERVED, since no actual flow
// was traced.

// credentialShapedSource matches the subset of taint.go's own taintSources
// pattern that plausibly carries a credential, narrower than the full
// pattern (which also matches non-credential sources like tool/model
// output) since this correlation is specifically about secrets.
var credentialShapedSource = regexp.MustCompile(`(?i)(os\.environ|os\.getenv|process\.env)`)

func nodeID(kind, refID, disambiguator string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + refID + "\x00" + disambiguator))
	return kind + ":" + hex.EncodeToString(sum[:8])
}

func findingNodeID(f skil.Finding) string {
	return nodeID("finding", f.RuleID, f.Fingerprint)
}

func observationNodeID(o skil.CapabilityObservation) string {
	return nodeID("capability", o.Capability, o.Location.File+"\x00"+o.Value)
}

// buildEvidenceGraph constructs the deterministic portion of the evidence
// graph (nodes for every finding/observation, OBSERVED taint-flow edges,
// INFERRED threat-chain and credential/network co-occurrence edges), then
// — only when provider is non-nil — attempts to verify each exfiltration-
// shaped candidate edge with one narrowly-scoped semantic query per
// candidate, promoting a confirmed candidate's edge to VERIFIED. A
// provider error, a degraded/incomplete response, or an unconfirmed
// candidate all leave the candidate at its prior (INFERRED or OBSERVED)
// state — semantic unavailability or disagreement never downgrades a
// deterministic signal that already stands on its own.
func buildEvidenceGraph(ctx context.Context, provider skil.SemanticProvider, ac skil.AnalysisContext, findings []skil.Finding, observations []skil.CapabilityObservation) *skil.EvidenceGraphSummary {
	var nodes []skil.EvidenceGraphNode
	var edges []skil.EvidenceGraphEdge
	seenNode := map[string]bool{}
	addNode := func(n skil.EvidenceGraphNode) {
		if seenNode[n.ID] {
			return
		}
		seenNode[n.ID] = true
		nodes = append(nodes, n)
	}

	findingNode := map[string]skil.EvidenceGraphNode{} // Fingerprint -> node
	for _, f := range findings {
		n := skil.EvidenceGraphNode{ID: findingNodeID(f), Kind: "finding", RefID: f.RuleID, State: skil.EvidenceObserved, Location: f.Location, Detail: f.Title}
		addNode(n)
		findingNode[f.Fingerprint] = n
	}
	for _, o := range observations {
		addNode(skil.EvidenceGraphNode{ID: observationNodeID(o), Kind: "capability", RefID: o.Capability, State: skil.EvidenceObserved, Location: o.Location, Detail: o.Value})
	}

	// OBSERVED taint-flow edges: every finding whose Evidence carries both
	// "source" and "sink" is a real, AST-traced data flow, not a
	// co-occurrence guess — the synthesized source endpoint and the
	// finding are connected at OBSERVED, backed entirely by that finding's
	// own already-computed evidence.
	type exfilCandidate struct {
		state    skil.EvidenceState
		sourceID string
		sinkID   string
		finding  skil.Finding
	}
	var candidates []exfilCandidate
	for _, f := range findings {
		source, hasSource := f.Evidence["source"].(string)
		sink, hasSink := f.Evidence["sink"].(string)
		if !hasSource || !hasSink {
			continue
		}
		sourceID := nodeID("taint-endpoint", "source", source+"\x00"+f.Location.File)
		addNode(skil.EvidenceGraphNode{ID: sourceID, Kind: "taint-endpoint", RefID: "source", State: skil.EvidenceObserved, Location: f.Location, Detail: source})
		findingID := findingNodeID(f)
		edges = append(edges, skil.EvidenceGraphEdge{
			From: sourceID, To: findingID, Relation: "flows-to", State: skil.EvidenceObserved,
			Rationale: "traced data flow from " + source + " to " + sink,
		})
		if sink == "network" && credentialShapedSource.MatchString(source) {
			candidates = append(candidates, exfilCandidate{state: skil.EvidenceObserved, sourceID: sourceID, sinkID: findingID, finding: f})
		}
	}

	// INFERRED threat-chain edges: reuse each SKIL-CHAIN-* finding's own
	// already-computed contributing_findings evidence — chains.go's own
	// doc comment already states these are co-occurrence, not
	// flow-verified, so INFERRED is the correct (not a new) claim here.
	for _, f := range findings {
		fingerprints, ok := f.Evidence["contributing_findings"].([]string)
		if !ok {
			continue
		}
		chainID := findingNodeID(f)
		for _, fp := range fingerprints {
			contributor, ok := findingNode[fp]
			if !ok {
				continue
			}
			edges = append(edges, skil.EvidenceGraphEdge{
				From: contributor.ID, To: chainID, Relation: "correlates-with", State: skil.EvidenceInferred,
				Rationale: "co-occurring signal contributing to threat chain " + f.RuleID,
			})
		}
	}

	// INFERRED credential-read + separate-network-operation co-occurrence:
	// a real, new correlation (not existing elsewhere) for exactly the
	// case static taint tracing cannot connect — a secret read and a
	// network operation in the same artifact with no traced flow between
	// them (different function, different file). Explicitly weaker than
	// the OBSERVED taint-flow edges above: no flow was traced, only
	// co-occurrence.
	var secretReads, networkOps []skil.Finding
	for _, f := range findings {
		switch {
		case f.RuleID == "SKIL-SEC-001" || f.RuleID == "SKIL-SECRET-HARDCODED" || f.RuleID == "SKIL-SECRET-TOKEN" || f.RuleID == "SKIL-SECRET-PRIVATE-KEY":
			secretReads = append(secretReads, f)
		case f.RuleID == "SKIL-NET-001":
			networkOps = append(networkOps, f)
		}
	}
	for _, secretFinding := range secretReads {
		for _, netFinding := range networkOps {
			secretID := findingNodeID(secretFinding)
			netID := findingNodeID(netFinding)
			edges = append(edges, skil.EvidenceGraphEdge{
				From: secretID, To: netID, Relation: "potential-exfiltration", State: skil.EvidenceInferred,
				Rationale: "credential/secret access and a separate outbound network operation co-occur in the same artifact with no traced flow between them",
			})
			candidates = append(candidates, exfilCandidate{state: skil.EvidenceInferred, sourceID: secretID, sinkID: netID, finding: netFinding})
		}
	}

	// Semantic verification: at most a small, bounded number of candidates
	// per scan, each one narrowly-scoped query — never a blanket new LLM
	// call, and only when --semantic is already configured.
	const maxCandidates = 5
	if provider != nil {
		for i, candidate := range candidates {
			if i >= maxCandidates {
				break
			}
			confirmed := verifyExfiltrationCandidate(ctx, provider, ac, candidate.finding)
			if !confirmed {
				continue
			}
			assessmentID := nodeID("semantic-assessment", "exfiltration_confirmed", candidate.finding.Fingerprint)
			addNode(skil.EvidenceGraphNode{
				ID: assessmentID, Kind: "semantic-assessment", RefID: "SKIL-SEM-EXFILTRATION-CONFIRMED",
				State: skil.EvidenceVerified, Location: candidate.finding.Location,
				Detail: "semantic provider independently confirmed exfiltration",
			})
			edges = append(edges, skil.EvidenceGraphEdge{
				From: assessmentID, To: candidate.sinkID, Relation: "confirms", State: skil.EvidenceVerified,
				Rationale: "semantic provider independently corroborated this correlation as genuine exfiltration",
			})
		}
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Relation < edges[j].Relation
	})
	summary := skil.EvidenceGraphSummary{Nodes: nodes, Edges: edges}
	summary.Digest = evidenceGraphDigest(summary)
	return &summary
}

func evidenceGraphDigest(summary skil.EvidenceGraphSummary) string {
	summary.Digest = ""
	payload, err := signing.CanonicalJSON(summary)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// verifyExfiltrationCandidate issues one narrowly-scoped semantic query
// asking the provider to independently confirm or refuse a single
// deterministic exfiltration candidate. Any provider-level problem
// (transport error, degraded/incomplete response) or an unconfirmed
// response returns false — never true on anything but an explicit,
// well-formed SKIL-SEM-EXFILTRATION-CONFIRMED finding from the provider.
func verifyExfiltrationCandidate(ctx context.Context, provider skil.SemanticProvider, ac skil.AnalysisContext, candidate skil.Finding) bool {
	var fileData []byte
	found := false
	for _, file := range ac.Artifact.Files {
		if file.Path == candidate.Location.File {
			fileData, found = file.Data, true
			break
		}
	}
	if !found || len(fileData) > maxSemanticBytes {
		return false // no real content to reason about, or it exceeds the transmission limit: decline rather than send an empty/truncated file.
	}
	request := skil.SemanticRequest{
		ArtifactDigest: ac.Artifact.Digest,
		Files:          map[string]string{candidate.Location.File: string(fileData)},
		Focus:          "exfiltration-correlation",
		PriorFindings:  []skil.Finding{candidate},
		NoTools:        true,
	}
	findings, diagnostics, err := analyzeSemanticPass(ctx, provider, request)
	if err != nil || semanticPassDegraded(diagnostics) {
		return false
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-SEM-EXFILTRATION-CONFIRMED" {
			return true
		}
	}
	return false
}
