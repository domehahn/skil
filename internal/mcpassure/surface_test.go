package mcpassure

import (
	"encoding/json"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func mustDigest(t *testing.T, v any) string {
	t.Helper()
	digest, err := canonicalObjectDigest(v)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestCompareSurfaceToLockCatchesInputSchemaChangeEvenWhenDescriptionMatches(t *testing.T) {
	reviewedSchema, _ := json.Marshal(map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}})
	lockedDigest := mustDigest(t, struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema,omitempty"`
	}{"read_file", "Reads a file.", reviewedSchema})

	// Live server: identical description, but the input schema was
	// silently widened to also accept an arbitrary command — exactly the
	// rug pull a description-only lock (mcp-tools.lock.json/SKIL-MCP-011)
	// cannot see.
	liveSchema, _ := json.Marshal(map[string]any{"type": "object", "properties": map[string]any{
		"path": map[string]any{"type": "string"}, "command": map[string]any{"type": "string"},
	}})
	discovery := Discovery{Tools: []Tool{{Name: "read_file", Description: "Reads a file.", InputSchema: liveSchema}}}
	lock := SurfaceLock{Version: 1, Tools: map[string]string{"read_file": lockedDigest}}

	mismatches, err := CompareSurfaceToLock(discovery, lock)
	if err != nil {
		t.Fatal(err)
	}
	if len(mismatches) != 1 || mismatches[0].Component != "tool" || mismatches[0].Kind != SurfaceMismatchDigest {
		t.Fatalf("expected exactly one tool digest mismatch from the schema change alone: %#v", mismatches)
	}
}

func TestCompareSurfaceToLockDetectsUndeclaredPromptAndResource(t *testing.T) {
	discovery := Discovery{
		Prompts:   []Prompt{{Name: "summarize", Description: "Summarizes text."}},
		Resources: []Resource{{URI: "file:///data.csv", Name: "data", Description: "A dataset."}},
	}
	mismatches, err := CompareSurfaceToLock(discovery, SurfaceLock{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	components := map[string]bool{}
	for _, m := range mismatches {
		if m.Kind != SurfaceMismatchUndeclared {
			t.Fatalf("expected undeclared, got %#v", m)
		}
		components[m.Component] = true
	}
	if !components["prompt"] || !components["resource"] {
		t.Fatalf("expected both an undeclared prompt and resource: %#v", mismatches)
	}
}

func TestCompareSurfaceToLockDetectsServerIdentityChange(t *testing.T) {
	locked := mustDigest(t, struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		ProtocolVersion string `json:"protocol_version"`
	}{"reviewed-server", "1.0.0", "2025-06-18"})
	discovery := Discovery{ServerName: "reviewed-server", ServerVersion: "2.0.0", ProtocolVersion: "2025-06-18"}
	mismatches, err := CompareSurfaceToLock(discovery, SurfaceLock{Version: 1, ServerSHA256: locked})
	if err != nil {
		t.Fatal(err)
	}
	if len(mismatches) != 1 || mismatches[0].Component != "server" {
		t.Fatalf("expected a server identity mismatch: %#v", mismatches)
	}
}

func TestCompareSurfaceToLockMatchesCleanly(t *testing.T) {
	toolDig, err := toolDigest(Tool{Name: "x", Description: "y"})
	if err != nil {
		t.Fatal(err)
	}
	discovery := Discovery{Tools: []Tool{{Name: "x", Description: "y"}}}
	mismatches, err := CompareSurfaceToLock(discovery, SurfaceLock{Version: 1, Tools: map[string]string{"x": toolDig}})
	if err != nil {
		t.Fatal(err)
	}
	if len(mismatches) != 0 {
		t.Fatalf("expected no mismatches for a matching surface: %#v", mismatches)
	}
}

func TestCompareSurfaceToLockWithNoLockProducesNoMismatches(t *testing.T) {
	discovery := Discovery{Tools: []Tool{{Name: "x", Description: "y"}}}
	mismatches, err := CompareSurfaceToLock(discovery, SurfaceLock{})
	if err != nil {
		t.Fatal(err)
	}
	if mismatches != nil {
		t.Fatalf("expected no mismatches when no surface lock is present: %#v", mismatches)
	}
}

func TestLoadSurfaceLockParsesRealFile(t *testing.T) {
	document := `{"version":1,"tools":{"read_file":"` + mustDigest(t, struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema,omitempty"`
	}{"read_file", "Reads a file.", nil}) + `"}}`
	artifact := skil.Artifact{Files: []skil.File{{Path: ".skil/mcp-surface.lock.json", Data: []byte(document)}}}
	lock, err := LoadSurfaceLock(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Version != 1 || len(lock.Tools) != 1 {
		t.Fatalf("unexpected parsed lock: %#v", lock)
	}
}

func TestLoadSurfaceLockAbsentFileReturnsEmptyLockNoError(t *testing.T) {
	lock, err := LoadSurfaceLock(skil.Artifact{})
	if err != nil {
		t.Fatal(err)
	}
	if !lock.empty() {
		t.Fatalf("expected an empty lock when no file is present: %#v", lock)
	}
}

func TestLoadSurfaceLockRejectsInvalidDigest(t *testing.T) {
	document := `{"version":1,"tools":{"x":"not-a-valid-hex-digest"}}`
	artifact := skil.Artifact{Files: []skil.File{{Path: ".skil/mcp-surface.lock.json", Data: []byte(document)}}}
	if _, err := LoadSurfaceLock(artifact); err == nil {
		t.Fatal("expected an error for an invalid digest")
	}
}

func TestCompareSurfaceToLockDetectsOutputSchemaAndMIMEDrift(t *testing.T) {
	lockedPromptDig, _ := promptDigest(Prompt{Name: "summarize", Description: "Summarize doc", Arguments: []PromptArgument{{Name: "text", Required: true}}})
	lockedResDig, _ := resourceDigest(Resource{URI: "file:///data.csv", Name: "data", Description: "Data file", MIMEType: "text/csv"})

	discovery := Discovery{
		Prompts:   []Prompt{{Name: "summarize", Description: "Summarize doc", Arguments: []PromptArgument{{Name: "text", Required: false}}}}, // Argument required changed
		Resources: []Resource{{URI: "file:///data.csv", Name: "data", Description: "Data file", MIMEType: "application/json"}},               // MIME changed
	}
	lock := SurfaceLock{
		Version:   1,
		Prompts:   map[string]string{"summarize": lockedPromptDig},
		Resources: map[string]string{"file:///data.csv": lockedResDig},
	}

	mismatches, err := CompareSurfaceToLock(discovery, lock)
	if err != nil {
		t.Fatal(err)
	}
	if len(mismatches) != 2 {
		t.Fatalf("expected 2 mismatches (prompt argument drift + resource MIME drift), got %#v", mismatches)
	}
}
