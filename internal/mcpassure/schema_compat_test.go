package mcpassure

import (
	"testing"

	"github.com/domehahn/skil/internal/completeness"
)

func TestNormalizeToolPayloadCamelAndSnakeCompatibility(t *testing.T) {
	camelJSON := []byte(`{
		"name": "query_db",
		"description": "Run a read-only query",
		"inputSchema": {"type": "object", "required": ["sql"], "properties": {"sql": {"type": "string"}}},
		"outputSchema": {"type": "object", "properties": {"rows": {"type": "array"}}}
	}`)
	snakeJSON := []byte(`{
		"name": "query_db",
		"description": "Run a read-only query",
		"input_schema": {"properties": {"sql": {"type": "string"}}, "required": ["sql"], "type": "object"},
		"output_schema": {"properties": {"rows": {"type": "array"}}, "type": "object"}
	}`)

	tCamel, err := NormalizeToolPayload(camelJSON)
	if err != nil {
		t.Fatalf("unexpected camelCase error: %v", err)
	}
	tSnake, err := NormalizeToolPayload(snakeJSON)
	if err != nil {
		t.Fatalf("unexpected snake_case error: %v", err)
	}

	dCamel, err := ToolDigest(tCamel)
	if err != nil {
		t.Fatal(err)
	}
	dSnake, err := ToolDigest(tSnake)
	if err != nil {
		t.Fatal(err)
	}
	if dCamel != dSnake {
		t.Fatalf("expected identical canonical tool digest across camelCase and snake_case, got %s != %s", dCamel, dSnake)
	}

	// Conflicting inputSchema and input_schema must fail closed.
	conflicting := []byte(`{
		"name": "query_db",
		"inputSchema": {"type": "object"},
		"input_schema": {"type": "string"}
	}`)
	if _, err := NormalizeToolPayload(conflicting); err == nil {
		t.Fatal("expected error on conflicting inputSchema and input_schema")
	}
}

func TestClassifyBinaryIdentityRejectsBasenameAsExact(t *testing.T) {
	// 1. Dynamic wrapper -> RUNTIME_UNKNOWN
	envWrap := ClassifyBinaryIdentity("env python3 script.py", "", "", "")
	if envWrap.ResolutionState != completeness.StateRuntimeUnknown {
		t.Fatalf("expected RUNTIME_UNKNOWN for env wrapper, got %s", envWrap.ResolutionState)
	}

	// 2. Shell builtin / PATH candidate -> PARTIAL
	printfCmd := ClassifyBinaryIdentity("printf '%s' foo", "", "", "")
	if printfCmd.ResolutionState != completeness.StatePartial {
		t.Fatalf("expected PARTIAL for bare printf, got %s", printfCmd.ResolutionState)
	}

	// 3. Bare basename without resolved path -> PARTIAL
	barePy := ClassifyBinaryIdentity("python3 app.py", "", "", "")
	if barePy.ResolutionState == completeness.StateExact {
		t.Fatal("basename-only command must never be classified as EXACT")
	}

	// 4. Resolved absolute path + valid SHA256 -> EXACT
	sha := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	exact := ClassifyBinaryIdentity("/usr/bin/python3", "/usr/bin/python3.11", "/usr/bin/python3.11", sha)
	if exact.ResolutionState != completeness.StateExact {
		t.Fatalf("expected EXACT when path and sha256 are pinned, got %s (%s)", exact.ResolutionState, exact.LimitationReason)
	}
}
