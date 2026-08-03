package analyzer

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

// MultiAgent covers ASP-08 / the taxonomy's Multi-Agent / A2A Security
// domain: identity spoofing between agents, delegated authority that
// escalates beyond the delegator's own scope, untrusted output from a peer
// agent reaching an execution sink, circular delegation chains, and
// cross-tenant agent access. Identity spoofing, untrusted output, and
// cross-tenant access are line-local code patterns handled the same way as
// Identity; delegation escalation and circular delegation are structural
// properties of a delegation graph and require parsing an agent-delegation
// manifest (any YAML/JSON document with an "agents" list of
// {id, scope, delegates_to}) rather than a single line.
type MultiAgent struct{ rules []RulePattern }

func NewMultiAgent() *MultiAgent {
	rule := func(id, title string, severity skil.Severity, expression, description, remediation string) RulePattern {
		return RulePattern{Rule: skil.Rule{
			ID: id, Title: title, Category: "a2a-security", Severity: severity,
			Description: description, Analysis: "multi-agent", AppliesTo: []string{"text", "code"},
			Remediation: remediation,
		}, Pattern: regexp.MustCompile("(?i)" + expression), Confidence: .9}
	}
	return &MultiAgent{rules: []RulePattern{
		rule("SKIL-A2A-001", "Unverified agent identity accepted", skil.SeverityHigh,
			`(?:agent_id|sender_agent|peer_agent|from_agent|caller_agent)\s*=\s*(?:request\.(?:headers|json|args|form)|payload\[|body\[|event\[)`,
			"An incoming agent identity claim is accepted directly from an unauthenticated request field instead of a verified credential or signature.",
			"Verify the calling agent's identity via a signed Agent Card, mTLS client identity, or a validated token before trusting a claimed agent_id."),
		rule("SKIL-A2A-003", "Unsanitized cross-agent output used unsafely", skil.SeverityHigh,
			`(?:eval|exec|os\.system|subprocess\.(?:run|call|Popen|check_output))\(\s*(?:agent_response|peer_response|a2a_response|agent_output|delegate_response|remote_agent_output)\b`,
			"Output received from another agent is passed into eval/exec/shell execution without validation or sanitization.",
			"Treat inter-agent output as untrusted input: validate and sanitize it and never pass it directly into eval, exec, or a shell."),
		rule("SKIL-A2A-005", "Cross-tenant agent access bypass", skil.SeverityCritical,
			`\b(?:verify_tenant\s*=\s*False|skip_tenant_check|bypass_tenant|cross_tenant\s*=\s*True)\b`,
			"An inter-agent call explicitly bypasses or skips tenant-boundary verification.",
			"Always verify the calling and target agent belong to the same tenant, or an explicitly authorized cross-tenant grant, before servicing the request."),
	}}
}

func (a *MultiAgent) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.multi-agent", Version: "1.0.0",
		Domain: "multi-agent", Subdomain: "identity-spoofing",
		Categories:    []string{"a2a-security"},
		AnalysisTypes: []string{"multi-agent"}, SupportedTypes: []string{"*"}}
}

func (a *MultiAgent) TaxonomyDomain() string    { return "multi-agent" }
func (a *MultiAgent) TaxonomySubdomain() string { return "identity-spoofing" }
func (a *MultiAgent) ControlIDs() []string {
	return []string{"A2A-001", "A2A-002", "A2A-003", "A2A-004", "A2A-005"}
}

func (a *MultiAgent) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if isText(file) {
			for lineNumber, text := range lines(file.Data) {
				for _, control := range a.rules {
					if control.Pattern.MatchString(text) {
						out = append(out, makeFinding(control, file, lineNumber+1, text))
					}
				}
			}
		}
		if !strings.Contains(string(file.Data), "delegates_to") {
			continue
		}
		var document any
		if err := yaml.Unmarshal(file.Data, &document); err != nil || !isStructuredMCPDocument(document) {
			continue
		}
		nodes := collectAgentDelegations(document)
		if len(nodes) == 0 {
			continue
		}
		for _, cycle := range detectDelegationCycles(nodes) {
			line, text := lineContaining(file.Data, cycle[0])
			path := strings.Join(cycle, " -> ") + " -> " + cycle[0]
			out = append(out, makeFinding(RulePattern{Rule: skil.Rule{
				ID: "SKIL-A2A-004", Title: "Circular agent delegation",
				Category: "a2a-security", Severity: skil.SeverityHigh,
				Description: "Agents delegate to each other in a cycle (" + path + "), which can be exploited to bypass a delegation-depth or authority check, or cause unbounded recursive delegation.",
				Analysis:    "multi-agent", Remediation: "Restructure delegation as a DAG with a bounded, strictly-decreasing authority at each hop; never delegate back to an ancestor.",
			}, Confidence: .95}, file, line, text))
		}
		for _, escalation := range detectScopeEscalations(nodes) {
			line, text := lineContaining(file.Data, escalation.Child)
			out = append(out, makeFinding(RulePattern{Rule: skil.Rule{
				ID: "SKIL-A2A-002", Title: "Delegated authority escalation",
				Category: "a2a-security", Severity: skil.SeverityCritical,
				Description: "Delegate \"" + escalation.Child + "\" holds scope(s) [" + strings.Join(escalation.Extra, ", ") + "] not granted to its delegator \"" + escalation.Parent + "\", violating child-scope-subset-of-parent-scope authority containment.",
				Analysis:    "multi-agent", Remediation: "Ensure a delegate's scope is always a subset of its delegator's scope; never widen authority across a delegation hop.",
			}, Confidence: .95}, file, line, text))
		}
	}
	return out, nil
}

type agentDelegationNode struct {
	ID          string
	DelegatesTo []string
	Scope       []string
}

// collectAgentDelegations recognizes any YAML/JSON document containing an
// "agents" list of maps with an id (or name), an optional scope list, and an
// optional delegates_to list of other agent ids — the minimal shape needed to
// reconstruct a delegation graph, independent of any single manifest schema.
func collectAgentDelegations(value any) []agentDelegationNode {
	var out []agentDelegationNode
	var visit func(any)
	visit = func(v any) {
		switch item := v.(type) {
		case map[string]any:
			if agents, ok := item["agents"].([]any); ok {
				for _, entry := range agents {
					m, ok := entry.(map[string]any)
					if !ok {
						continue
					}
					id, _ := m["id"].(string)
					if id == "" {
						id, _ = m["name"].(string)
					}
					if id == "" {
						continue
					}
					out = append(out, agentDelegationNode{
						ID:          id,
						DelegatesTo: mcpStringSlice(m["delegates_to"]),
						Scope:       mcpStringSlice(m["scope"]),
					})
				}
			}
			for _, key := range sortedMapKeys(item) {
				visit(item[key])
			}
		case []any:
			for _, child := range item {
				visit(child)
			}
		}
	}
	visit(value)
	return out
}

// detectDelegationCycles runs a DFS over the delegates_to graph and returns
// each distinct cycle once, ordered deterministically by the sorted node ids
// visited (so results are stable across runs regardless of map iteration).
func detectDelegationCycles(nodes []agentDelegationNode) [][]string {
	adjacency := map[string][]string{}
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		adjacency[n.ID] = n.DelegatesTo
		ids = append(ids, n.ID)
	}
	sort.Strings(ids)

	var cycles [][]string
	seenCycle := map[string]bool{}
	visited := map[string]bool{}
	onStack := map[string]bool{}
	var stack []string

	var dfs func(string)
	dfs = func(node string) {
		visited[node] = true
		onStack[node] = true
		stack = append(stack, node)
		children := append([]string{}, adjacency[node]...)
		sort.Strings(children)
		for _, child := range children {
			if onStack[child] {
				start := indexOfString(stack, child)
				cycle := append([]string{}, stack[start:]...)
				key := strings.Join(sortedStrings(cycle), ",")
				if !seenCycle[key] {
					seenCycle[key] = true
					cycles = append(cycles, cycle)
				}
				continue
			}
			if !visited[child] {
				dfs(child)
			}
		}
		stack = stack[:len(stack)-1]
		onStack[node] = false
	}
	for _, id := range ids {
		if !visited[id] {
			dfs(id)
		}
	}
	return cycles
}

type agentScopeEscalation struct {
	Parent string
	Child  string
	Extra  []string
}

// detectScopeEscalations flags every delegation edge where the delegate's
// declared scope is not a subset of its delegator's declared scope. Agents
// with no declared scope are skipped: an absent scope declaration is a
// contract-conformance gap handled elsewhere, not evidence of escalation.
func detectScopeEscalations(nodes []agentDelegationNode) []agentScopeEscalation {
	byID := map[string]agentDelegationNode{}
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
		ids = append(ids, n.ID)
	}
	sort.Strings(ids)

	var out []agentScopeEscalation
	for _, parentID := range ids {
		parent := byID[parentID]
		if len(parent.Scope) == 0 {
			continue
		}
		parentScope := map[string]bool{}
		for _, s := range parent.Scope {
			parentScope[s] = true
		}
		children := append([]string{}, parent.DelegatesTo...)
		sort.Strings(children)
		for _, childID := range children {
			child, ok := byID[childID]
			if !ok || len(child.Scope) == 0 {
				continue
			}
			var extra []string
			for _, s := range child.Scope {
				if !parentScope[s] {
					extra = append(extra, s)
				}
			}
			if len(extra) > 0 {
				out = append(out, agentScopeEscalation{Parent: parentID, Child: childID, Extra: sortedStrings(extra)})
			}
		}
	}
	return out
}

func indexOfString(items []string, target string) int {
	for i, item := range items {
		if item == target {
			return i
		}
	}
	return -1
}

func sortedStrings(items []string) []string {
	out := append([]string{}, items...)
	sort.Strings(out)
	return out
}
