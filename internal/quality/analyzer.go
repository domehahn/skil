package quality

import (
	"path/filepath"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// Analyze evaluates a skill artifact for quality, completeness, documentation, and structural integrity.
func Analyze(art *skil.Artifact) ([]skil.Finding, skil.Status) {
	if art == nil || len(art.Files) == 0 {
		return nil, skil.StatusPass
	}

	var findings []skil.Finding
	status := skil.StatusPass

	var skillMD *skil.File
	for i := range art.Files {
		if filepath.Base(art.Files[i].Path) == "SKILL.md" {
			skillMD = &art.Files[i]
			break
		}
	}

	// Rule 1: SKIL-QUAL-001 - Metadata & Header
	if skillMD == nil {
		findings = append(findings, skil.Finding{
			ID:          "SKIL-QUAL-001",
			RuleID:      "SKIL-QUAL-001",
			Category:    "quality_metadata",
			Severity:    skil.SeverityMedium,
			Confidence:  0.95,
			Title:       "Missing SKILL.md Documentation",
			Message:     "Skill artifact lacks a primary SKILL.md documentation manifest",
			Remediation: "Add a standard SKILL.md file describing purpose, instructions, and examples.",
			Location: skil.Location{
				File: "SKILL.md",
			},
			Fingerprint: "qual-001-missing-skillmd",
		})
		status = skil.StatusWarn
		return findings, status
	}

	content := string(skillMD.Data)
	words := strings.Fields(content)

	// Rule 2: SKIL-QUAL-002 - Instruction Completeness & Clarity
	if len(words) < 15 {
		findings = append(findings, skil.Finding{
			ID:          "SKIL-QUAL-002",
			RuleID:      "SKIL-QUAL-002",
			Category:    "quality_completeness",
			Severity:    skil.SeverityLow,
			Confidence:  0.90,
			Title:       "Incomplete Skill Instructions",
			Message:     "SKILL.md instructions are extremely brief (under 15 words) and may lack clarity",
			Remediation: "Elaborate instructions to guide AI agent behavior deterministically.",
			Location: skil.Location{
				File:      skillMD.Path,
				StartLine: 1,
			},
			Fingerprint: "qual-002-brief-instructions",
		})
		if status == skil.StatusPass {
			status = skil.StatusWarn
		}
	}

	// Rule 3: SKIL-QUAL-003 - Example Coverage
	contentLower := strings.ToLower(content)
	if !strings.Contains(contentLower, "example") && !strings.Contains(contentLower, "usage") && !strings.Contains(contentLower, "```") {
		findings = append(findings, skil.Finding{
			ID:          "SKIL-QUAL-003",
			RuleID:      "SKIL-QUAL-003",
			Category:    "quality_examples",
			Severity:    skil.SeverityLow,
			Confidence:  0.85,
			Title:       "Missing Usage Examples",
			Message:     "SKILL.md does not contain code blocks or explicit usage examples",
			Remediation: "Provide at least one concrete example demonstrating how the skill should be invoked.",
			Location: skil.Location{
				File: skillMD.Path,
			},
			Fingerprint: "qual-003-missing-examples",
		})
		if status == skil.StatusPass {
			status = skil.StatusWarn
		}
	}

	// Rule 4: SKIL-QUAL-004 - Safety Constraints & Rollback
	hasDestructiveAction := strings.Contains(contentLower, "deploy") || strings.Contains(contentLower, "delete") || strings.Contains(contentLower, "apply")
	hasSafetyOrRollback := strings.Contains(contentLower, "rollback") || strings.Contains(contentLower, "verify") || strings.Contains(contentLower, "confirm") || strings.Contains(contentLower, "dry-run") || strings.Contains(contentLower, "safety")

	if hasDestructiveAction && !hasSafetyOrRollback {
		findings = append(findings, skil.Finding{
			ID:          "SKIL-QUAL-004",
			RuleID:      "SKIL-QUAL-004",
			Category:    "quality_safety",
			Severity:    skil.SeverityMedium,
			Confidence:  0.88,
			Title:       "Missing Safety Constraints or Rollback Strategy",
			Message:     "Skill performs state-modifying actions without documenting verification, dry-run, or rollback procedures",
			Remediation: "Specify safety constraints, confirmation gates, or rollback steps for state-modifying operations.",
			Location: skil.Location{
				File: skillMD.Path,
			},
			Fingerprint: "qual-004-missing-rollback",
		})
		if status == skil.StatusPass {
			status = skil.StatusWarn
		}
	}

	return findings, status
}
