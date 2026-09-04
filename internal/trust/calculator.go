package trust

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/pkg/skil"
)

// EvaluateTrust computes an explainable, multi-metric TrustAssessment from input signals.
func EvaluateTrust(inputs TrustInputs, weights TrustWeights) TrustAssessment {
	if weights.SecurityWeight == 0 {
		weights = DefaultTrustWeights()
	}

	var deductions []TrustDeduction
	var recommendations []string

	if inputs.IsRevoked {
		deductions = append(deductions, TrustDeduction{
			Category:       "lifecycle",
			PointsDeducted: 100,
			Reason:         "Skill version has been explicitly REVOKED due to security or governance action",
		})
		return TrustAssessment{
			ArtifactName: getArtifactName(inputs.Artifact),
			Version:      getArtifactVersion(inputs.Artifact),
			Digest:       getArtifactDigest(inputs.Artifact),
			TrustScore: TrustScore{
				Score:      0.0,
				Breakdown:  TrustBreakdown{},
				Deductions: deductions,
			},
			TrustLevel:        LevelRevoked,
			AdmissionDecision: registry.DecisionReject,
			Recommendations:   []string{"Do not execute or publish this revoked skill artifact."},
			Timestamp:         time.Now().UTC(),
		}
	}

	// 1. Security Score
	secScore := 100.0
	for _, f := range inputs.Findings {
		if f.Suppressed {
			continue
		}
		var pts float64
		switch f.Severity {
		case skil.SeverityCritical:
			pts = 40.0
		case skil.SeverityHigh:
			pts = 20.0
		case skil.SeverityMedium:
			pts = 10.0
		case skil.SeverityLow:
			pts = 5.0
		default:
			pts = 2.0
		}
		secScore -= pts
		deductions = append(deductions, TrustDeduction{
			Category:       "security",
			RuleID:         f.RuleID,
			PointsDeducted: pts,
			Reason:         fmt.Sprintf("[%s] %s", f.Severity, f.Message),
			Evidence:       f.Location.File,
		})
	}
	secScore = math.Max(0, secScore)

	// 2. Quality Score
	qualScore := 100.0
	for _, qf := range inputs.QualityFindings {
		pts := 10.0
		qualScore -= pts
		deductions = append(deductions, TrustDeduction{
			Category:       "quality",
			RuleID:         qf.RuleID,
			PointsDeducted: pts,
			Reason:         qf.Message,
			Evidence:       qf.Location.File,
		})
	}
	qualScore = math.Max(0, qualScore)

	// 3. Evaluation & Skill Lift Score
	evalScore := 100.0
	if inputs.SkillLift < 0 {
		pts := 35.0
		evalScore -= pts
		deductions = append(deductions, TrustDeduction{
			Category:       "evaluation",
			PointsDeducted: pts,
			Reason:         fmt.Sprintf("Negative Skill Lift observed (%.1f%%)", inputs.SkillLift*100),
		})
		recommendations = append(recommendations, "Skill impairs agent performance; refine instructions or tool usage.")
	} else if inputs.SkillLift > 0 {
		evalScore = math.Min(100.0, 75.0+inputs.SkillLift*100.0)
	}

	if inputs.PassAtK > 0 && inputs.PassAtK < 0.8 {
		pts := 20.0
		evalScore -= pts
		deductions = append(deductions, TrustDeduction{
			Category:       "evaluation",
			PointsDeducted: pts,
			Reason:         fmt.Sprintf("Low pass@k evaluation stability (%.1f%%)", inputs.PassAtK*100),
		})
	}
	evalScore = math.Max(0, evalScore)

	// 4. Provenance & Signature Score
	provScore := 100.0
	if !inputs.IsSigned {
		pts := 50.0
		provScore -= pts
		deductions = append(deductions, TrustDeduction{
			Category:       "signature",
			PointsDeducted: pts,
			Reason:         "Skill artifact is unsigned",
		})
		recommendations = append(recommendations, "Sign the package using `skil package sign` or DSSE Ed25519 key.")
	}
	if !inputs.HasProvenance {
		pts := 50.0
		provScore -= pts
		deductions = append(deductions, TrustDeduction{
			Category:       "provenance",
			PointsDeducted: pts,
			Reason:         "Missing build provenance / SLSA attestation statement",
		})
		recommendations = append(recommendations, "Generate build provenance using `skil provenance create`.")
	}
	provScore = math.Max(0, provScore)

	// 5. Permission Risk Score
	permScore := 100.0
	highRiskPerms := extractHighRiskPermissions(inputs.Artifact, inputs.Findings)
	for _, perm := range highRiskPerms {
		pts := 15.0
		permScore -= pts
		deductions = append(deductions, TrustDeduction{
			Category:       "permissions",
			PointsDeducted: pts,
			Reason:         fmt.Sprintf("High-risk permission requested: %s", perm),
		})
	}
	permScore = math.Max(0, permScore)

	// 6. Duplicate Risk Score
	dupScore := 100.0
	if inputs.DuplicateResult != nil {
		rel := inputs.DuplicateResult.Relationship
		mostSimilar := ""
		semScore := 0.0
		if len(inputs.DuplicateResult.Matches) > 0 {
			mostSimilar = inputs.DuplicateResult.Matches[0].Entry.Name
			semScore = inputs.DuplicateResult.Matches[0].Scores.Semantic
		}

		switch rel {
		case registry.RelationshipExactDuplicate, registry.RelationshipSemanticDuplicate:
			pts := 80.0
			dupScore -= pts
			deductions = append(deductions, TrustDeduction{
				Category:       "duplicate",
				PointsDeducted: pts,
				Reason:         fmt.Sprintf("Skill is a %s of existing skill %s", rel, mostSimilar),
			})
		case registry.RelationshipSubset:
			pts := 40.0
			dupScore -= pts
			deductions = append(deductions, TrustDeduction{
				Category:       "duplicate",
				PointsDeducted: pts,
				Reason:         fmt.Sprintf("Skill is a subset capability of existing skill %s", mostSimilar),
			})
		case registry.RelationshipHighSimilarity, registry.RelationshipSuperset:
			pts := 20.0
			dupScore -= pts
			deductions = append(deductions, TrustDeduction{
				Category:       "duplicate",
				PointsDeducted: pts,
				Reason:         fmt.Sprintf("High functional similarity (%.0f%%) with existing skill %s", semScore*100, mostSimilar),
			})
		}
	}
	dupScore = math.Max(0, dupScore)

	// 7. Runtime Stability Score
	runtimeScore := 100.0

	// Weighted Total Calculation
	totalScore := (secScore * weights.SecurityWeight) +
		(qualScore * weights.QualityWeight) +
		(evalScore * weights.EvaluationWeight) +
		(provScore * weights.ProvenanceWeight) +
		(permScore * weights.PermissionWeight) +
		(dupScore * weights.DuplicateWeight) +
		(runtimeScore * weights.RuntimeStabilityWeight)

	totalScore = math.Round(totalScore*10.0) / 10.0

	// Determine Trust Level
	var level TrustLevel
	switch {
	case totalScore >= 90.0 && inputs.IsSigned && inputs.HasProvenance && secScore == 100.0:
		level = LevelVerified
	case totalScore >= 80.0:
		level = LevelTrusted
	case totalScore >= 65.0:
		level = LevelReviewed
	case totalScore >= 45.0:
		level = LevelRestricted
	default:
		level = LevelUntrusted
	}

	// Determine Admission Decision
	var decision registry.AdmissionDecision
	switch {
	case level == LevelUntrusted || secScore < 50.0 || (inputs.DuplicateResult != nil && (inputs.DuplicateResult.Relationship == registry.RelationshipExactDuplicate || inputs.DuplicateResult.Relationship == registry.RelationshipSemanticDuplicate)):
		decision = registry.DecisionReject
	case level == LevelRestricted || level == LevelReviewed || (inputs.DuplicateResult != nil && inputs.DuplicateResult.Relationship == registry.RelationshipSubset):
		decision = registry.DecisionReview
	case totalScore < 85.0:
		decision = registry.DecisionAcceptWithWarning
	default:
		decision = registry.DecisionAccept
	}

	return TrustAssessment{
		ArtifactName: getArtifactName(inputs.Artifact),
		Version:      getArtifactVersion(inputs.Artifact),
		Digest:       getArtifactDigest(inputs.Artifact),
		TrustScore: TrustScore{
			Score: totalScore,
			Breakdown: TrustBreakdown{
				SecurityScore:         math.Round(secScore*10.0) / 10.0,
				QualityScore:          math.Round(qualScore*10.0) / 10.0,
				EvaluationScore:       math.Round(evalScore*10.0) / 10.0,
				ProvenanceScore:       math.Round(provScore*10.0) / 10.0,
				PermissionRiskScore:   math.Round(permScore*10.0) / 10.0,
				DuplicateRiskScore:    math.Round(dupScore*10.0) / 10.0,
				RuntimeStabilityScore: math.Round(runtimeScore*10.0) / 10.0,
			},
			Deductions: deductions,
		},
		TrustLevel:        level,
		AdmissionDecision: decision,
		Recommendations:   recommendations,
		Timestamp:         time.Now().UTC(),
	}
}

func getArtifactName(art *skil.Artifact) string {
	if art != nil && art.Name != "" {
		return art.Name
	}
	return "unknown-skill"
}

func getArtifactVersion(art *skil.Artifact) string {
	if art != nil {
		return art.Version
	}
	return ""
}

func getArtifactDigest(art *skil.Artifact) string {
	if art != nil {
		return art.SubjectDigest()
	}
	return ""
}

func extractHighRiskPermissions(art *skil.Artifact, findings []skil.Finding) []string {
	var perms []string
	seen := make(map[string]bool)

	for _, f := range findings {
		ruleUpper := strings.ToUpper(f.RuleID)
		if strings.Contains(ruleUpper, "SHELL") || strings.Contains(ruleUpper, "SH-") {
			if !seen["shell_execution"] {
				perms = append(perms, "shell_execution")
				seen["shell_execution"] = true
			}
		}
		if strings.Contains(ruleUpper, "SECRET") || strings.Contains(ruleUpper, "CREDENTIAL") {
			if !seen["secrets_access"] {
				perms = append(perms, "secrets_access")
				seen["secrets_access"] = true
			}
		}
		if strings.Contains(ruleUpper, "NET-001") || strings.Contains(ruleUpper, "SSRF") {
			if !seen["unrestricted_network"] {
				perms = append(perms, "unrestricted_network")
				seen["unrestricted_network"] = true
			}
		}
	}
	return perms
}
