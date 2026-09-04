package drift

import (
	"fmt"
	"sort"

	"github.com/domehahn/skil/internal/registry"
	"github.com/domehahn/skil/internal/trust"
	"github.com/domehahn/skil/pkg/skil"
)

// DriftReport holds the side-by-side version comparison and drift classification results.
type DriftReport struct {
	BaseSkill           string                     `json:"base_skill" yaml:"base_skill"`
	BaseVersion         string                     `json:"base_version" yaml:"base_version"`
	TargetSkill         string                     `json:"target_skill" yaml:"target_skill"`
	TargetVersion       string                     `json:"target_version" yaml:"target_version"`
	BaseTrustScore      float64                    `json:"base_trust_score" yaml:"base_trust_score"`
	TargetTrustScore    float64                    `json:"target_trust_score" yaml:"target_trust_score"`
	ScoreDelta          float64                    `json:"score_delta" yaml:"score_delta"`
	HasPermissionDrift  bool                       `json:"has_permission_drift" yaml:"has_permission_drift"`
	HasCapabilityDrift  bool                       `json:"has_capability_drift" yaml:"has_capability_drift"`
	NewSecurityFindings []skil.Finding             `json:"new_security_findings,omitempty" yaml:"new_security_findings,omitempty"`
	AddedCapabilities   []string                   `json:"added_capabilities,omitempty" yaml:"added_capabilities,omitempty"`
	RemovedCapabilities []string                   `json:"removed_capabilities,omitempty" yaml:"removed_capabilities,omitempty"`
	AddedPermissions    []string                   `json:"added_permissions,omitempty" yaml:"added_permissions,omitempty"`
	RemovedPermissions  []string                   `json:"removed_permissions,omitempty" yaml:"removed_permissions,omitempty"`
	Decision            registry.AdmissionDecision `json:"decision" yaml:"decision"`
	Recommendations     []string                   `json:"recommendations,omitempty" yaml:"recommendations,omitempty"`
}

// CompareVersions evaluates drift and differences between a baseline skill version and a target skill version.
func CompareVersions(baseArt *skil.Artifact, baseAssessment *trust.TrustAssessment, baseCaps registry.CapabilityFingerprint, baseFindings []skil.Finding,
	targetArt *skil.Artifact, targetAssessment *trust.TrustAssessment, targetCaps registry.CapabilityFingerprint, targetFindings []skil.Finding) *DriftReport {

	baseName := "base-skill"
	baseVer := ""
	if baseArt != nil {
		if baseArt.Name != "" {
			baseName = baseArt.Name
		}
		baseVer = baseArt.Version
	}

	targetName := "target-skill"
	targetVer := ""
	if targetArt != nil {
		if targetArt.Name != "" {
			targetName = targetArt.Name
		}
		targetVer = targetArt.Version
	}

	baseScore := 0.0
	if baseAssessment != nil {
		baseScore = baseAssessment.TrustScore.Score
	}

	targetScore := 0.0
	if targetAssessment != nil {
		targetScore = targetAssessment.TrustScore.Score
	}

	scoreDelta := targetScore - baseScore

	// Compare Security Findings
	baseFindingMap := make(map[string]bool)
	for _, f := range baseFindings {
		baseFindingMap[f.RuleID] = true
	}

	var newFindings []skil.Finding
	for _, tf := range targetFindings {
		if !baseFindingMap[tf.RuleID] {
			newFindings = append(newFindings, tf)
		}
	}

	// Compare Permissions
	basePermMap := make(map[string]bool)
	for _, p := range baseCaps.Permissions {
		basePermMap[p] = true
	}
	targetPermMap := make(map[string]bool)
	for _, p := range targetCaps.Permissions {
		targetPermMap[p] = true
	}

	var addedPerms []string
	for p := range targetPermMap {
		if !basePermMap[p] {
			addedPerms = append(addedPerms, p)
		}
	}
	var removedPerms []string
	for p := range basePermMap {
		if !targetPermMap[p] {
			removedPerms = append(removedPerms, p)
		}
	}

	// Compare Capabilities (Actions + Tools)
	baseCapMap := make(map[string]bool)
	for _, a := range baseCaps.Actions {
		baseCapMap[a] = true
	}
	for _, t := range baseCaps.Tools {
		baseCapMap[t] = true
	}

	targetCapMap := make(map[string]bool)
	for _, a := range targetCaps.Actions {
		targetCapMap[a] = true
	}
	for _, t := range targetCaps.Tools {
		targetCapMap[t] = true
	}

	var addedCaps []string
	for c := range targetCapMap {
		if !baseCapMap[c] {
			addedCaps = append(addedCaps, c)
		}
	}
	var removedCaps []string
	for c := range baseCapMap {
		if !targetCapMap[c] {
			removedCaps = append(removedCaps, c)
		}
	}

	sort.Strings(addedPerms)
	sort.Strings(removedPerms)
	sort.Strings(addedCaps)
	sort.Strings(removedCaps)

	hasPermDrift := len(addedPerms) > 0
	hasCapDrift := len(addedCaps) > 0

	decision := registry.DecisionAccept
	var recommendations []string

	if len(newFindings) > 0 || hasPermDrift || scoreDelta < -10.0 {
		decision = registry.DecisionReview
		if hasPermDrift {
			recommendations = append(recommendations, fmt.Sprintf("Review added permissions: %v", addedPerms))
		}
		if len(newFindings) > 0 {
			recommendations = append(recommendations, fmt.Sprintf("Audit %d new security findings introduced in target version.", len(newFindings)))
		}
	}

	return &DriftReport{
		BaseSkill:           baseName,
		BaseVersion:         baseVer,
		TargetSkill:         targetName,
		TargetVersion:       targetVer,
		BaseTrustScore:      baseScore,
		TargetTrustScore:    targetScore,
		ScoreDelta:          float64(int(scoreDelta*10.0)) / 10.0,
		HasPermissionDrift:  hasPermDrift,
		HasCapabilityDrift:  hasCapDrift,
		NewSecurityFindings: newFindings,
		AddedCapabilities:   addedCaps,
		RemovedCapabilities: removedCaps,
		AddedPermissions:    addedPerms,
		RemovedPermissions:  removedPerms,
		Decision:            decision,
		Recommendations:     recommendations,
	}
}
