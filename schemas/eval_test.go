package schemas

import "testing"

func TestEvalSchemaPreservesCategoriesAndValidatesContainment(t *testing.T) {
	for _, category := range []string{"direct-injection", "custom-existing-category", "containment-escape"} {
		document := []byte(`version: 1
name: compatibility
type: adversarial
input: {message: test}
tools: {available: []}
expect: {assertions: [containment_compliant]}
attack: {category: ` + category + `}
containment:
  required: true
  require_enforcement: true
  allowed_targets:
    network.outbound: [challenge.internal]
`)
		if err := ValidateYAML("eval-v1.schema.json", document); err != nil {
			t.Fatalf("category %q or containment extension was rejected: %v", category, err)
		}
	}
}

func TestEvalSchemaRejectsUnknownContainmentFields(t *testing.T) {
	document := []byte(`version: 1
name: invalid
type: behavioral
input: {message: test}
tools: {available: []}
expect: {}
containment:
  required: true
  adapter_says_allowed: true
`)
	if err := ValidateYAML("eval-v1.schema.json", document); err == nil {
		t.Fatal("unknown adapter-controlled containment field must be rejected")
	}
}
