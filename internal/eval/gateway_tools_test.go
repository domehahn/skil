package eval

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestArtifactReadToolUsesOnlyCanonicalArtifactView(t *testing.T) {
	tool := NewArtifactReadTool(skil.Artifact{Files: []skil.File{{Path: "docs/readme.md", Data: []byte("safe")}}})
	operation, err := tool.Operation(map[string]any{"path": "docs/readme.md"})
	if err != nil {
		t.Fatal(err)
	}
	if operation.Capability != "filesystem.read" || operation.Target != "docs/readme.md" {
		t.Fatalf("unexpected operation: %#v", operation)
	}
	value, err := tool.Execute(context.Background(), map[string]any{"path": "docs/readme.md"})
	if err != nil || value.(map[string]any)["content"] != "safe" {
		t.Fatalf("unexpected result: %#v, %v", value, err)
	}
	for _, path := range []string{"../secret", "docs/../secret", "/etc/passwd"} {
		if _, err := tool.Operation(map[string]any{"path": path}); err == nil {
			t.Errorf("unsafe path %q accepted", path)
		}
	}
}
