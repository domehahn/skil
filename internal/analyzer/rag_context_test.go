package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestRAGContextDetectsBoundaryConfusionAndExecFlow(t *testing.T) {
	analyzer := NewRAGContext()

	artifact := skil.Artifact{
		Name: "rag-poison-skill",
		Files: []skil.File{
			{
				Path: "prompt.py",
				Data: []byte("System Context: {retrieved_docs}\nexec(retrieved_doc.content)"),
			},
		},
	}

	findings, err := analyzer.Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (boundary confusion + exec flow), got %d", len(findings))
	}
}
