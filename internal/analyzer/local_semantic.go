package analyzer

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// LocalSemantic performs deterministic cross-file intent/implementation
// analysis. It complements, rather than impersonates, optional model-backed
// semantic review and never transmits artifact content.
type LocalSemantic struct{}

func NewLocalSemantic() *LocalSemantic { return &LocalSemantic{} }

func (*LocalSemantic) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.local-semantic", Version: "1.0.0",
		Domain: "behavioral", Subdomain: "hidden-triggers",
		Categories:    []string{"intent-integrity", "semantic-composition"},
		AnalysisTypes: []string{"semantic"}, SupportedTypes: []string{"text"},
	}
}

type semanticClaim struct {
	name, capability, statement string
	pattern                     *regexp.Regexp
	rules                       map[string]bool
	file                        skil.File
	line                        int
}

func (*LocalSemantic) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	claims := collectSemanticClaims(ac.Artifact)
	if len(claims) == 0 {
		return nil, nil
	}
	var observations []skil.Finding
	for _, analyzer := range []skil.Analyzer{NewPythonAST(), NewStructuredAST(), NewBoundary()} {
		findings, err := analyzer.Analyze(ctx, ac)
		if err != nil {
			return nil, err
		}
		observations = append(observations, findings...)
	}
	var out []skil.Finding
	for _, claim := range claims {
		var conflicting []string
		for _, observation := range observations {
			if claim.rules[observation.RuleID] {
				conflicting = append(conflicting,
					observation.RuleID+"@"+observation.Location.File+":"+strconv.Itoa(observation.Location.StartLine))
			}
		}
		if len(conflicting) == 0 {
			continue
		}
		sort.Strings(conflicting)
		rule := RulePattern{Rule: skil.Rule{
			ID: "SKIL-INTENT-IMPLEMENTATION", Title: "Intent and implementation divergence",
			Category: "intent-integrity", Severity: skil.SeverityHigh,
			Description: "Implementation behavior contradicts an explicit bounded-behavior statement.",
			Analysis:    "semantic", Remediation: "Align executable behavior with the documented intent and reviewed contract.",
		}, Confidence: .97}
		finding := makeFinding(rule, claim.file, claim.line, claim.statement)
		finding.Evidence["claim"] = claim.name
		finding.Evidence["capability"] = claim.capability
		finding.Evidence["conflicting_observations"] = conflicting
		finding.Evidence["engine"] = "deterministic-cross-file-intent"
		out = append(out, finding)
	}
	return out, nil
}

func collectSemanticClaims(artifact skil.Artifact) []semanticClaim {
	templates := []semanticClaim{
		{name: "no outbound network", capability: "network.outbound",
			pattern: regexp.MustCompile(`(?i)\b(?:does not|do not|never|must not|without)\b.{0,60}\b(?:network|internet|external (?:service|request|connection)|outbound)\b`),
			rules:   map[string]bool{"SKIL-NET-001": true, "SKIL-BOUNDARY-SSRF": true, "SKIL-BOUNDARY-METADATA": true}},
		{name: "read-only", capability: "filesystem.write",
			pattern: regexp.MustCompile(`(?i)\b(?:read[- ]only|does not (?:modify|write)|never (?:modify|write)|must not (?:modify|write))\b`),
			rules:   map[string]bool{"SKIL-FS-001": true}},
		{name: "no process execution", capability: "commands.execute",
			pattern: regexp.MustCompile(`(?i)\b(?:does not|do not|never|must not)\b.{0,50}\b(?:execute|run|spawn|invoke)\b.{0,30}\b(?:commands?|process(?:es)?|shell)\b`),
			rules: map[string]bool{"SKIL-PY-001": true, "SKIL-PY-002": true, "SKIL-PY-REFLECT-EXEC": true,
				"SKIL-SH-001": true, "SKIL-SH-004": true, "SKIL-JS-001": true, "SKIL-JS-002": true}},
		{name: "no secret access", capability: "secrets.read",
			pattern: regexp.MustCompile(`(?i)\b(?:does not|do not|never|must not)\b.{0,50}\b(?:read|access|collect)\b.{0,30}\b(?:secrets?|credentials?|tokens?|environment variables?)\b`),
			rules:   map[string]bool{"SKIL-SEC-001": true}},
		{name: "limited scope", capability: "scope.creep",
			pattern: regexp.MustCompile(`(?i)\b(?:only|limited|sole|single|specific|bounded)\b.{0,40}\b(?:purpose|task|function|scope|domain|operation)\b`),
			rules:   map[string]bool{"SKIL-PL-001": true, "SKIL-EX-001": true, "SKIL-PERSISTENCE-STARTUP": true, "SKIL-BOUNDARY-AGENT-STATE": true, "SKIL-BOUNDARY-MCP-CONFIG": true, "SKIL-BOUNDARY-PEER-SKILL": true, "SKIL-AGENT-SELF-MODIFY": true}},
		{name: "no memory", capability: "memory.persist",
			pattern: regexp.MustCompile(`(?i)\b(?:does not|do not|never|must not|without)\b.{0,50}\b(?:store|save|persist|remember|retain|keep|record)\b.{0,30}\b(?:data|state|context|history|information|conversation)\b`),
			rules:   map[string]bool{"SKIL-DS-001": true, "SKIL-BUILD-COMMAND": true, "SKIL-BUILD-STATE": true}},
		{name: "no data exfiltration", capability: "data.exfiltrate",
			pattern: regexp.MustCompile(`(?i)\b(?:does not|do not|never|must not|without)\b.{0,50}\b(?:exfiltrate|send|transmit|transmit|upload|transfer)\b.{0,30}\b(?:data|content|files?|artifact)\b`),
			rules:   map[string]bool{"SKIL-TAINT-NETWORK": true, "SKIL-BOUNDARY-CROSS-DOMAIN": true}},
	}
	var claims []semanticClaim
	for _, file := range artifact.Files {
		if !isText(file) || !strings.HasSuffix(strings.ToLower(file.Path), ".md") {
			continue
		}
		for number, line := range lines(file.Data) {
			for _, template := range templates {
				if template.pattern.MatchString(line) {
					template.file, template.line, template.statement = file, number+1, line
					claims = append(claims, template)
				}
			}
		}
	}
	return claims
}
