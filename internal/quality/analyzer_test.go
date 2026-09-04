package quality

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestAnalyze_CleanQualitySkill(t *testing.T) {
	art := &skil.Artifact{
		Name: "clean-skill",
		Files: []skil.File{
			{
				Path: "SKILL.md",
				Data: []byte(`# Clean Skill

This skill deploys workloads cleanly into Kubernetes.

## Safety & Rollback

Before running apply, run a --dry-run verification step. If deployment fails, execute a rollback to previous revision.

## Usage Example

` + "```bash" + `
skil deploy --verify
` + "```" + `
`),
			},
		},
	}

	findings, status := Analyze(art)
	if status != skil.StatusPass {
		t.Errorf("Expected StatusPass for clean skill, got %s", status)
	}

	if len(findings) > 0 {
		t.Errorf("Expected 0 findings for clean skill, got %d", len(findings))
	}
}

func TestAnalyze_DeficientSkill(t *testing.T) {
	art := &skil.Artifact{
		Name: "deficient-skill",
		Files: []skil.File{
			{
				Path: "SKILL.md",
				Data: []byte("deploy application to production"), // Brief, no safety, no examples
			},
		},
	}

	findings, status := Analyze(art)
	if status != skil.StatusWarn {
		t.Errorf("Expected StatusWarn for deficient skill, got %s", status)
	}

	if len(findings) < 2 {
		t.Errorf("Expected at least 2 quality findings for deficient skill, got %d", len(findings))
	}
}
