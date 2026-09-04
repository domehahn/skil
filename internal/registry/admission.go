package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

type AdmissionEvaluator struct {
	config AdmissionConfig
}

func NewAdmissionEvaluator(config AdmissionConfig) *AdmissionEvaluator {
	return &AdmissionEvaluator{
		config: config,
	}
}

func (ae *AdmissionEvaluator) EvaluateAdmission(ctx context.Context, analysis DuplicateAnalysisResult) AdmissionResult {
	if !ae.config.Enabled {
		return AdmissionResult{
			Decision:       DecisionAccept,
			Relationship:   RelationshipDistinct,
			Candidate:      analysis.Candidate.Name,
			Reason:         "Registry admission control is disabled in configuration.",
			Recommendation: "Proceed with publish.",
		}
	}

	res := AdmissionResult{
		Decision:       DecisionAccept,
		Relationship:   analysis.Relationship,
		Candidate:      analysis.Candidate.Name,
		Reason:         analysis.Reason,
		Recommendation: analysis.Recommendation,
	}

	var mostSimilarName string
	var mostSimilarScores SimilarityScore
	var capOverlap CapabilityOverlapResult

	if len(analysis.Matches) > 0 {
		topMatch := analysis.Matches[0]
		mostSimilarName = topMatch.Entry.Name
		mostSimilarScores = topMatch.Scores
		capOverlap = topMatch.CapabilityDetail
		res.UniqueCapabilities = capOverlap.UniqueCapabilities
		res.OverlappingCapabilities = capOverlap.OverlappingCapabilities
	}

	res.MostSimilarSkill = mostSimilarName
	res.Scores = mostSimilarScores
	res.CapabilityOverlap = capOverlap

	// Determine decision based on policy mapping
	var policyDecision AdmissionDecision
	switch analysis.Relationship {
	case RelationshipExactDuplicate:
		policyDecision = ae.config.Policies.ExactDuplicate
	case RelationshipSemanticDuplicate:
		policyDecision = ae.config.Policies.SemanticDuplicate
	case RelationshipHighSimilarity:
		policyDecision = ae.config.Policies.HighSimilarity
	case RelationshipCapabilityOverlap:
		policyDecision = ae.config.Policies.CapabilityOverlap
	case RelationshipSubset:
		policyDecision = ae.config.Policies.Subset
	case RelationshipSuperset:
		policyDecision = ae.config.Policies.Superset
	case RelationshipComplementary:
		policyDecision = ae.config.Policies.Complementary
	case RelationshipDistinct:
		policyDecision = ae.config.Policies.Distinct
	default:
		policyDecision = DecisionAccept
	}

	res.Decision = policyDecision

	// Check allow rules / suppressions
	for _, rule := range ae.config.AllowRules {
		if ruleMatches(rule, analysis.Candidate.Name, mostSimilarName) {
			if rule.Expires.IsZero() || time.Now().Before(rule.Expires) {
				ruleCopy := rule
				res.AllowedBy = &ruleCopy
				res.Decision = DecisionAcceptWithWarning
				res.Reason = fmt.Sprintf("Admission permitted by explicit allow rule (%s): %s", rule.Candidate, rule.Reason)
				res.Recommendation = "Allowed by policy exception."
				break
			}
		}
	}

	return res
}

func ruleMatches(rule AllowRule, candidateName, relatedToName string) bool {
	candMatch := rule.Candidate == "*" || rule.Candidate == candidateName || strings.Contains(candidateName, rule.Candidate)
	if !candMatch {
		return false
	}
	if rule.RelatedTo == "" || rule.RelatedTo == "*" {
		return true
	}
	return rule.RelatedTo == relatedToName || strings.Contains(relatedToName, rule.RelatedTo)
}

func GenerateSARIFReport(adm AdmissionResult, sarifFile string) ([]byte, error) {
	ruleID, ruleTitle := mapRelationshipToSARIFRule(adm.Relationship)
	severity := mapDecisionToSARIFLevel(adm.Decision)

	sarif := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "skil-registry",
						"version":        skil.Version,
						"informationUri": "https://github.com/domehahn/skil",
						"rules": []map[string]interface{}{
							{
								"id":                   ruleID,
								"shortDescription":     map[string]string{"text": ruleTitle},
								"fullDescription":      map[string]string{"text": adm.Reason},
								"defaultConfiguration": map[string]string{"level": severity},
							},
						},
					},
				},
				"results": []map[string]interface{}{
					{
						"ruleId":  ruleID,
						"level":   severity,
						"message": map[string]string{"text": fmt.Sprintf("[%s] %s (Candidate: %s, Existing: %s)", adm.Decision, adm.Reason, adm.Candidate, adm.MostSimilarSkill)},
						"locations": []map[string]interface{}{
							{
								"physicalLocation": map[string]interface{}{
									"artifactLocation": map[string]string{"uri": "SKILL.md"},
								},
							},
						},
					},
				},
			},
		},
	}
	return json.MarshalIndent(sarif, "", "  ")
}

func mapRelationshipToSARIFRule(rel RelationshipType) (id string, title string) {
	switch rel {
	case RelationshipExactDuplicate:
		return "SKIL-REG-001", "Exact Skill Duplicate"
	case RelationshipSemanticDuplicate:
		return "SKIL-REG-002", "Semantic Skill Duplicate"
	case RelationshipHighSimilarity:
		return "SKIL-REG-003", "High Skill Similarity"
	case RelationshipCapabilityOverlap:
		return "SKIL-REG-004", "Skill Capability Overlap"
	case RelationshipSubset:
		return "SKIL-REG-005", "Skill Capabilities Subset"
	case RelationshipSuperset:
		return "SKIL-REG-006", "Skill Capabilities Superset"
	default:
		return "SKIL-REG-000", "Skill Admission Notice"
	}
}

func mapDecisionToSARIFLevel(dec AdmissionDecision) string {
	switch dec {
	case DecisionReject:
		return "error"
	case DecisionReview:
		return "warning"
	case DecisionAcceptWithWarning:
		return "warning"
	default:
		return "note"
	}
}
