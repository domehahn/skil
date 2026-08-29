package analyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"gopkg.in/yaml.v3"
)

const (
	MaxYAMLAliases     = 50
	MaxYAMLNodes       = 10_000
	MaxJSONDepth       = 100
	MaxJSONElements    = 50_000
	MaxTreeSitterDepth = 100
)

var (
	ErrYAMLAliasBomb  = errors.New("yaml alias expansion limit exceeded")
	ErrYAMLNodeLimit  = errors.New("yaml total node limit exceeded")
	ErrJSONDepthLimit = errors.New("json nesting depth limit exceeded")
)

// ValidateYAMLBounds checks a YAML payload for alias explosion bombs and excessive node counts.
func ValidateYAMLBounds(data []byte) error {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return err
	}

	aliases := 0
	nodes := 0

	var walk func(n *yaml.Node, depth int) error
	walk = func(n *yaml.Node, depth int) error {
		if n == nil {
			return nil
		}
		nodes++
		if nodes > MaxYAMLNodes {
			return ErrYAMLNodeLimit
		}
		if n.Kind == yaml.AliasNode {
			aliases++
			if aliases > MaxYAMLAliases {
				return ErrYAMLAliasBomb
			}
		}
		for _, child := range n.Content {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}

	return walk(&node, 0)
}

// ValidateJSONBounds checks a JSON payload for excessive nesting depth or element counts.
func ValidateJSONBounds(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	depth := 0
	elements := 0

	for {
		t, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		switch v := t.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
				if depth > MaxJSONDepth {
					return ErrJSONDepthLimit
				}
			} else if v == '}' || v == ']' {
				depth--
			}
		}
		elements++
		if elements > MaxJSONElements {
			return errors.New("json total element count limit exceeded")
		}
	}
	return nil
}
