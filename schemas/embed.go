// Package schemas provides the canonical embedded JSON Schemas used at runtime.
package schemas

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

//go:embed *.schema.json
var files embed.FS

func ValidateAll() error {
	names, err := files.ReadDir(".")
	if err != nil {
		return err
	}
	for _, entry := range names {
		if entry.IsDir() {
			continue
		}
		data, err := files.ReadFile(entry.Name())
		if err != nil {
			return err
		}
		var schemaValue any
		if err := json.Unmarshal(data, &schemaValue); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource(entry.Name(), schemaValue); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if _, err := compiler.Compile(entry.Name()); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
	}
	return nil
}

func ValidateYAML(name string, data []byte) error {
	schemaData, err := files.ReadFile(name)
	if err != nil {
		return fmt.Errorf("load embedded schema %s: %w", name, err)
	}
	compiler := jsonschema.NewCompiler()
	var schemaValue any
	if err := json.Unmarshal(schemaData, &schemaValue); err != nil {
		return fmt.Errorf("decode embedded schema %s: %w", name, err)
	}
	if err := compiler.AddResource(name, schemaValue); err != nil {
		return fmt.Errorf("compile schema resource: %w", err)
	}
	schema, err := compiler.Compile(name)
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}
	var value any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return err
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(normalized, &value); err != nil {
		return err
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("JSON Schema validation failed: %w", err)
	}
	return nil
}
