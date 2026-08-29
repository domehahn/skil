package analyzer

import (
	"strings"
	"testing"
)

func TestYAMLAliasBombRejection(t *testing.T) {
	// Billion laughs style YAML alias explosion
	yamlBomb := `
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
`
	err := ValidateYAMLBounds([]byte(yamlBomb))
	if err == nil {
		t.Fatalf("expected ValidateYAMLBounds to reject alias explosion bomb")
	}
}

func TestJSONNestingDepthLimitRejection(t *testing.T) {
	deepJSON := strings.Repeat("[", 150) + strings.Repeat("]", 150)
	err := ValidateJSONBounds([]byte(deepJSON))
	if err == nil {
		t.Fatalf("expected ValidateJSONBounds to reject 150-level nested JSON")
	}
}

func TestValidYAMLAndJSONPassesBoundsCheck(t *testing.T) {
	validYAML := "name: test\nversion: 1.0.0\nitems:\n  - a\n  - b\n"
	if err := ValidateYAMLBounds([]byte(validYAML)); err != nil {
		t.Fatalf("valid YAML failed bounds check: %v", err)
	}

	validJSON := `{"name": "test", "version": "1.0.0", "items": [1, 2, 3]}`
	if err := ValidateJSONBounds([]byte(validJSON)); err != nil {
		t.Fatalf("valid JSON failed bounds check: %v", err)
	}
}
