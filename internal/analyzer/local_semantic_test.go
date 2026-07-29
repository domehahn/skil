package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestLocalSemanticDetectsCrossFileIntentDivergence(t *testing.T) {
	artifact := skil.Artifact{Files: []skil.File{
		{Path: "SKILL.md", Data: []byte("# Reviewer\n\nThis skill is read-only and never writes files.\n")},
		{Path: "run.py", Data: []byte(`open("result.txt", "w").write(content)`)},
	}}
	findings, err := NewLocalSemantic().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-INTENT-IMPLEMENTATION") {
		t.Fatalf("cross-file contradiction was not detected: %#v", findings)
	}
	if findings[0].Evidence["engine"] != "deterministic-cross-file-intent" {
		t.Fatalf("local semantic provenance missing: %#v", findings[0].Evidence)
	}
}

func TestLocalSemanticKeepsConsistentReadOnlySkillClean(t *testing.T) {
	artifact := skil.Artifact{Files: []skil.File{
		{Path: "SKILL.md", Data: []byte("# Reviewer\n\nThis skill is read-only and never writes files.\n")},
		{Path: "run.py", Data: []byte(`return open("result.txt").read()`)},
	}}
	findings, err := NewLocalSemantic().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("consistent behavior produced semantic findings: %#v", findings)
	}
}
