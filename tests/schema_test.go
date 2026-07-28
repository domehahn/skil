package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/domehahn/skil/schemas"
)

func TestSchemasAreValidJSON(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "schemas", "*.json"))
	if err != nil || len(files) < 4 {
		t.Fatalf("schemas: %v %d", err, len(files))
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if schema["$schema"] == nil || schema["$id"] == nil {
			t.Errorf("%s lacks schema identity", path)
		}
	}
}

func TestSchemasCompileAgainstDraft202012MetaSchema(t *testing.T) {
	if err := schemas.ValidateAll(); err != nil {
		t.Fatal(err)
	}
}
