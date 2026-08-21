package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// Deterministic Threat-Chain Correlation.
//
// A single skill's own scan can contain several individually low-to-high
// severity findings that, together, indicate a specific, well-known
// multi-stage attack pattern — the same idea internal/compose applies
// across skills, applied here within one skill's own already-computed
// Findings and CapabilityObservations. This is deliberately NOT a general
// graph/taint correlation engine and NOT semantic/ML-scored: each chain is
// a fixed, named, reviewable combination of existing rule IDs and
// capabilities, so a chain firing is exactly as explainable and
// reproducible as any single rule — the finding's evidence lists exactly
// which constituent findings satisfied it.
//
// Chains only ever combine signals that already independently exist in
// BuiltinRules()/CapabilityObservation vocabulary; correlateThreatChains
// never invents a new detection primitive, only a narrative over ones that
// already fired.

// chainSignal is satisfied if ANY of RuleIDs matches a Finding.RuleID, or
// (when Capability is set) if any CapabilityObservation has that exact
// Capability value, in the same scan.
type chainSignal struct {
	RuleIDs    []string
	Capability string
}

func (s chainSignal) matches(findings []skil.Finding, observations []skil.CapabilityObservation) ([]skil.Finding, bool) {
	if s.Capability != "" {
		for _, observation := range observations {
			if observation.Capability == s.Capability {
				// Capability-satisfied signals contribute no Finding
				// evidence of their own; the chain's Evidence records the
				// capability instead (see correlateThreatChains).
				return nil, true
			}
		}
		return nil, false
	}
	var matched []skil.Finding
	ids := make(map[string]bool, len(s.RuleIDs))
	for _, id := range s.RuleIDs {
		ids[id] = true
	}
	for _, finding := range findings {
		if ids[finding.RuleID] {
			matched = append(matched, finding)
		}
	}
	return matched, len(matched) > 0
}

// threatChain is a fixed, named combination of chainSignals. A chain fires
// only when every signal is independently satisfied somewhere in the same
// scan.
type threatChain struct {
	Rule    RulePattern
	Signals []chainSignal
}

// threatChainCatalog is the fixed, reviewable set of correlated attack
// patterns. Each entry's rationale is documented inline; adding a new one
// requires the same review as adding any other rule.
func threatChainCatalog() []threatChain {
	return []threatChain{
		{
			// A hidden or obfuscated instruction is concerning on its own
			// (SKIL-PI-*/SKIL-OBF-001/SKIL-UNI-003/SKIL-MCP-002/SKIL-MCP-004
			// already flag it), but it is a materially different, more
			// urgent situation when the same artifact also has a
			// confirmed path from untrusted content to an execution sink
			// — the hidden instruction is no longer merely a policy
			// violation risk, it has somewhere to actually run.
			Rule: RulePattern{Rule: skil.Rule{
				ID: "SKIL-CHAIN-INJECT-EXEC", Title: "Hidden instruction chains into an execution sink",
				Category: "threat-chain", Severity: skil.SeverityCritical, Analysis: "chain",
				Description: "A hidden, encoded, or injected instruction and a confirmed taint flow to a dynamic-execution sink both exist in the same skill — the injected instruction has a concrete path to run, not just a theoretical one.",
				Remediation: "Remove the hidden/encoded instruction and the unvalidated execution sink; treat this as a single confirmed attack chain, not two independent findings.",
			}, Confidence: .95},
			Signals: []chainSignal{
				{RuleIDs: []string{"SKIL-PI-HIDDEN-COMMENT", "SKIL-PI-MD-HIDDEN-COMMENT", "SKIL-OBF-001", "SKIL-UNI-003", "SKIL-MCP-002", "SKIL-MCP-004"}},
				{RuleIDs: []string{"SKIL-TAINT-EXECUTION", "SKIL-TAINT-OUTPUT-EXECUTION"}},
			},
		},
		{
			// An unpinned/mutable dependency resolution and a suspicious
			// or outright malicious dependency are each their own finding,
			// but together they describe a concrete supply-chain
			// compromise stage: the artifact both names something
			// suspicious AND resolves it in a way a rug pull can silently
			// change later without re-triggering review.
			Rule: RulePattern{Rule: skil.Rule{
				ID: "SKIL-CHAIN-SUPPLY-CHAIN-COMPROMISE", Title: "Mutable resolution of a suspicious dependency",
				Category: "threat-chain", Severity: skil.SeverityCritical, Analysis: "chain",
				Description: "A dependency or MCP tool resolves from a mutable, unpinned identity, and a separate finding shows a suspicious or known-malicious dependency in the same artifact — an identity that can silently change combined with content already worth distrusting.",
				Remediation: "Pin every dependency and MCP tool identity to an exact, integrity-checked version, and remove or replace the suspicious dependency; treat this as a single confirmed supply-chain risk.",
			}, Confidence: .93},
			Signals: []chainSignal{
				{RuleIDs: []string{"SKIL-DEP-001", "SKIL-MCP-003"}},
				{RuleIDs: []string{"SKIL-DEP-002", "SKIL-DEP-MALICIOUS", "SKIL-DEP-VULN"}},
			},
		},
		{
			// Instructing an agent to misrepresent its memory/identity is
			// itself a state-integrity finding; it becomes a distinct,
			// more serious multi-agent deception scenario when the same
			// skill also forwards output to another agent without
			// validation — the false state is not just self-contained
			// theater, it can propagate to a downstream agent that trusts
			// it.
			Rule: RulePattern{Rule: skil.Rule{
				ID: "SKIL-CHAIN-DECEPTIVE-MULTIAGENT", Title: "Identity deception propagated to another agent",
				Category: "threat-chain", Severity: skil.SeverityCritical, Analysis: "chain",
				Description: "The skill is instructed to falsely represent its identity or memory state, and separately forwards output to another agent without validation — the false state can propagate to a downstream agent that trusts it.",
				Remediation: "Remove the false-identity/false-memory instruction and add validation or a trust boundary before forwarding output to another agent.",
			}, Confidence: .9},
			Signals: []chainSignal{
				{RuleIDs: []string{"SKIL-MEMORY-FALSE-RESET", "SKIL-MEMORY-FALSE-REPRESENTATION"}},
				{RuleIDs: []string{"SKIL-TAINT-OUTPUT-CROSS-AGENT"}},
			},
		},
		{
			// A confusable/deceptive hostname or Unicode-deceptive text is
			// one finding; a parameter or environment-variable read that
			// requests credentials is another. Together, in the same
			// artifact, they describe a credential-harvesting page/tool
			// dressed up to look legitimate — the deception exists
			// specifically to make the credential request look
			// trustworthy.
			Rule: RulePattern{Rule: skil.Rule{
				ID: "SKIL-CHAIN-DECEPTIVE-CREDENTIAL-HARVEST", Title: "Deceptive presentation paired with credential collection",
				Category: "threat-chain", Severity: skil.SeverityCritical, Analysis: "chain",
				Description: "A Unicode-deceptive or confusable hostname/text and a separate finding requesting secrets, credentials, or environment variables both exist in the same skill — the deceptive presentation exists specifically to make the credential request look legitimate.",
				Remediation: "Remove the deceptive presentation and the credential-collection instruction; investigate whether this is a phishing-style tool disguised as a legitimate one.",
			}, Confidence: .9},
			Signals: []chainSignal{
				{RuleIDs: []string{"SKIL-UNI-001", "SKIL-UNI-002"}},
				{RuleIDs: []string{"SKIL-MCP-004", "SKIL-SEC-001"}},
			},
		},
	}
}

// correlateThreatChains runs the fixed threat-chain catalog over one
// scan's already-computed Findings and CapabilityObservations and returns
// one Finding per chain that fires. It is a pure post-processing pass —
// order-independent of which analyzer produced each contributing signal —
// so it is called once, after every analyzer has run, from Registry.Scan.
func correlateThreatChains(findings []skil.Finding, observations []skil.CapabilityObservation) []skil.Finding {
	var out []skil.Finding
	for _, chain := range threatChainCatalog() {
		var contributing []skil.Finding
		var capabilities []string
		satisfied := true
		for _, signal := range chain.Signals {
			matched, ok := signal.matches(findings, observations)
			if !ok {
				satisfied = false
				break
			}
			contributing = append(contributing, matched...)
			if signal.Capability != "" {
				capabilities = append(capabilities, signal.Capability)
			}
		}
		if !satisfied {
			continue
		}
		out = append(out, chainFinding(chain.Rule, contributing, capabilities))
	}
	return out
}

func chainFinding(rule RulePattern, contributing []skil.Finding, capabilities []string) skil.Finding {
	sort.Slice(contributing, func(i, j int) bool { return contributing[i].Fingerprint < contributing[j].Fingerprint })
	fingerprints := make([]string, 0, len(contributing))
	ruleIDs := make([]string, 0, len(contributing))
	seenRule := map[string]bool{}
	for _, finding := range contributing {
		fingerprints = append(fingerprints, finding.Fingerprint)
		if !seenRule[finding.RuleID] {
			seenRule[finding.RuleID] = true
			ruleIDs = append(ruleIDs, finding.RuleID)
		}
	}
	sort.Strings(ruleIDs)
	location := skil.Location{File: "SKILL.md", StartLine: 1}
	if len(contributing) > 0 {
		location = contributing[0].Location
	}
	finding := makeFinding(rule, skil.File{Path: location.File}, location.StartLine, strings.Join(ruleIDs, "+"))
	finding.Location = location
	finding.Evidence["contributing_rules"] = ruleIDs
	finding.Evidence["contributing_findings"] = fingerprints
	if len(capabilities) > 0 {
		sort.Strings(capabilities)
		finding.Evidence["contributing_capabilities"] = capabilities
	}
	finding.Message = fmt.Sprintf("Chain %s correlates %s", rule.Rule.ID, strings.Join(ruleIDs, ", "))
	return finding
}
