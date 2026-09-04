package attackpath

import (
	"fmt"
	"strings"

	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/pkg/skil"
)

type NodeType string

const (
	NodeSkill         NodeType = "SKILL"
	NodeTool          NodeType = "TOOL"
	NodePermission    NodeType = "PERMISSION"
	NodeResource      NodeType = "RESOURCE"
	NodeDataClass     NodeType = "DATA_CLASS"
	NodeNetworkTarget NodeType = "NETWORK_TARGET"
	NodeMCPServer     NodeType = "MCP_SERVER"
)

type EdgeType string

const (
	EdgeUses          EdgeType = "USES"
	EdgeRequires      EdgeType = "REQUIRES"
	EdgeAccesses      EdgeType = "ACCESSES"
	EdgeProvides      EdgeType = "PROVIDES"
	EdgeExfiltratesTo EdgeType = "EXFILTRATES_TO"
)

type GraphNode struct {
	ID    string   `json:"id" yaml:"id"`
	Type  NodeType `json:"type" yaml:"type"`
	Label string   `json:"label" yaml:"label"`
	Owner string   `json:"owner,omitempty" yaml:"owner,omitempty"`
}

type GraphEdge struct {
	From string   `json:"from" yaml:"from"`
	To   string   `json:"to" yaml:"to"`
	Type EdgeType `json:"type" yaml:"type"`
}

type CapabilityGraph struct {
	Nodes map[string]GraphNode `json:"nodes" yaml:"nodes"`
	Edges []GraphEdge          `json:"edges" yaml:"edges"`
}

func NewCapabilityGraph() *CapabilityGraph {
	return &CapabilityGraph{
		Nodes: make(map[string]GraphNode),
		Edges: make([]GraphEdge, 0),
	}
}

func (g *CapabilityGraph) AddNode(node GraphNode) {
	g.Nodes[node.ID] = node
}

func (g *CapabilityGraph) AddEdge(from, to string, edgeType EdgeType) {
	g.Edges = append(g.Edges, GraphEdge{
		From: from,
		To:   to,
		Type: edgeType,
	})
}

type AttackPathResult struct {
	HasRiskyPath bool             `json:"has_risky_path" yaml:"has_risky_path"`
	Findings     []skil.Finding   `json:"findings" yaml:"findings"`
	Graph        *CapabilityGraph `json:"graph,omitempty" yaml:"graph,omitempty"`
}

// AddSkillCapabilities populates the graph with a skill's declared and extracted capability fingerprint.
func (g *CapabilityGraph) AddSkillCapabilities(skillName string, caps registry.CapabilityFingerprint, findings []skil.Finding) {
	skillID := "skill:" + skillName
	g.AddNode(GraphNode{
		ID:    skillID,
		Type:  NodeSkill,
		Label: skillName,
	})

	for _, tool := range caps.Tools {
		toolID := "tool:" + tool
		g.AddNode(GraphNode{ID: toolID, Type: NodeTool, Label: tool})
		g.AddEdge(skillID, toolID, EdgeUses)
	}

	for _, perm := range caps.Permissions {
		permID := "perm:" + perm
		g.AddNode(GraphNode{ID: permID, Type: NodePermission, Label: perm})
		g.AddEdge(skillID, permID, EdgeRequires)
	}

	for _, res := range caps.Resources {
		resID := "res:" + res
		g.AddNode(GraphNode{ID: resID, Type: NodeResource, Label: res})
		g.AddEdge(skillID, resID, EdgeAccesses)
	}

	// Inspect findings for secret reads or network egress
	for _, f := range findings {
		ruleUpper := strings.ToUpper(f.RuleID)
		if strings.Contains(ruleUpper, "SECRET") || strings.Contains(ruleUpper, "CREDENTIAL") {
			dataID := "data:credentials"
			g.AddNode(GraphNode{ID: dataID, Type: NodeDataClass, Label: "Credentials / Secrets"})
			g.AddEdge(skillID, dataID, EdgeAccesses)
		}
		if strings.Contains(ruleUpper, "NET-001") || strings.Contains(ruleUpper, "SSRF") {
			netID := "net:external"
			g.AddNode(GraphNode{ID: netID, Type: NodeNetworkTarget, Label: "External Egress"})
			g.AddEdge(skillID, netID, EdgeExfiltratesTo)
		}
	}
}

// AnalyzeCrossSkillAttackPaths evaluates multi-skill graph compositions for exfiltration or privilege escalation paths.
func AnalyzeCrossSkillAttackPaths(g *CapabilityGraph) AttackPathResult {
	var findings []skil.Finding

	secretReaders := make(map[string]string)  // skillID -> skillLabel
	networkSenders := make(map[string]string) // skillID -> skillLabel

	for _, edge := range g.Edges {
		if edge.To == "data:credentials" && edge.Type == EdgeAccesses {
			if node, ok := g.Nodes[edge.From]; ok {
				secretReaders[node.ID] = node.Label
			}
		}
		if edge.To == "net:external" && edge.Type == EdgeExfiltratesTo {
			if node, ok := g.Nodes[edge.From]; ok {
				networkSenders[node.ID] = node.Label
			}
		}
	}

	// Correlate secret reader skill + separate network sender skill
	for readerID, readerLabel := range secretReaders {
		for senderID, senderLabel := range networkSenders {
			if readerID != senderID {
				findings = append(findings, skil.Finding{
					ID:         "SKIL-ATTACK-001",
					RuleID:     "SKIL-ATTACK-001",
					Category:   "attack_path_exfiltration",
					Severity:   skil.SeverityHigh,
					Confidence: 0.92,
					Title:      "Cross-Skill Exfiltration Attack Path Detected",
					Message: fmt.Sprintf("Composed attack path discovered: Skill '%s' reads secrets/credentials, and Skill '%s' exposes unrestricted network egress.",
						readerLabel, senderLabel),
					Remediation: "Scope secret reader permissions or restrict network egress capabilities across composed agent skills.",
					Location: skil.Location{
						File: fmt.Sprintf("%s -> %s", readerLabel, senderLabel),
					},
					Fingerprint: fmt.Sprintf("attack-001-%s-%s", readerLabel, senderLabel),
				})
			}
		}
	}

	return AttackPathResult{
		HasRiskyPath: len(findings) > 0,
		Findings:     findings,
		Graph:        g,
	}
}
