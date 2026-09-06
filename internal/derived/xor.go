package derived

import (
	"bytes"
	"strconv"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

// Code-proven repeating-XOR reconstruction.
//
// Every other transform in this package decodes an encoding textually
// present in the artifact bytes themselves (Base64, hex, URL-encoding,
// Unicode confusables, ...) — the encoding scheme is fixed and its input
// is exactly the token being decoded. Repeating-XOR is different: the
// "encoding" is a Python expression, and reversing it safely requires
// knowing that both the key and the payload are themselves static (not
// runtime-computed) before it is safe to apply the fixed algorithm at
// all. This transform only fires when that can be proven structurally:
//
//   - the exact idiom `bytes(<b> ^ <key>[<i> % len(<key>)] for <i>, <b> in
//     enumerate(<payload>))` is matched via a strict tree-sitter Python
//     AST shape (loop variable names must agree between the generator
//     body and its for-clause; the key identifier must appear identically
//     in both subscript positions) — not a regex guess at "something that
//     looks XOR-shaped";
//   - <key> and <payload> both resolve, via a same-file scan for a
//     `name = b"..."` byte-literal assignment, to concrete, static bytes
//     (bounded in length) — a runtime-computed key or payload (read from
//     an argument, a function call, user input, ...) is never resolved,
//     and the transform silently declines rather than guessing;
//   - the decoded result passes the same printable() gate every other
//     decode transform in this package already uses, so a coincidental
//     structural match against non-XOR-shaped code that happens to
//     produce garbage is not surfaced as a misleading "reconstruction".
//
// No brute-force key search, no speculative XOR against arbitrary
// candidate keys: the algorithm and both inputs must already be provable
// from the code exactly as written.

const (
	maxXORPayloadBytes = 16 << 10 // bounded output, matching this package's other decode transforms
	maxXORKeyBytes     = 256
)

func mayContainPythonXORReconstruction(data []byte) bool {
	return bytes.Contains(data, []byte("enumerate(")) && bytes.Contains(data, []byte("bytes(")) && bytes.Contains(data, []byte("^"))
}

// decodePythonRepeatingXOR parses data as Python (tree-sitter is error-
// tolerant: non-Python content simply produces no matching node, not a
// fatal error) and reconstructs any provably-static repeating-XOR call it
// finds.
func decodePythonRepeatingXOR(data []byte) ([]replacement, []string) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(tree_sitter_python.Language())); err != nil {
		return nil, nil
	}
	tree := parser.Parse(data, nil)
	if tree == nil {
		return nil, nil
	}
	defer tree.Close()
	literals := collectByteLiterals(tree.RootNode(), data)
	var out []replacement
	walkXORTree(tree.RootNode(), func(node *tree_sitter.Node) {
		if node.Kind() != "call" {
			return
		}
		function := node.ChildByFieldName("function")
		args := node.ChildByFieldName("arguments")
		if function == nil || function.Utf8Text(data) != "bytes" || args == nil {
			return
		}
		// A single, unparenthesized generator expression argument
		// (`bytes(x for x in y)`) is tree-sitter-python's own direct
		// "arguments" child, not wrapped in an argument_list the way every
		// other call's arguments are -- both shapes must be recognized.
		var gen *tree_sitter.Node
		switch args.Kind() {
		case "generator_expression":
			gen = args
		case "argument_list":
			if args.NamedChildCount() != 1 {
				return
			}
			gen = args.NamedChild(0)
		default:
			return
		}
		keyName, payloadName, ok := matchRepeatingXORGenerator(gen, data)
		if !ok {
			return
		}
		key, ok := literals[keyName]
		if !ok || len(key) == 0 || len(key) > maxXORKeyBytes {
			return
		}
		payload, ok := literals[payloadName]
		if !ok || len(payload) == 0 || len(payload) > maxXORPayloadBytes {
			return
		}
		decoded := make([]byte, len(payload))
		for i := range payload {
			decoded[i] = payload[i] ^ key[i%len(key)]
		}
		if !printable(decoded) {
			return
		}
		out = append(out, replacement{
			start: int(node.StartByte()), end: int(node.EndByte()), data: decoded,
			detail: "statically reconstructed repeating-XOR decode (proven key, payload, and algorithm)",
		})
	})
	return out, nil
}

// matchRepeatingXORGenerator structurally matches
// `<b> ^ <key>[<i> % len(<key>)] for <i>, <b> in enumerate(<payload>)`
// against gen (a generator_expression node), requiring the loop index and
// element variable names to agree exactly between the generator body and
// its for-clause, and the key identifier to appear identically in both
// subscript positions. Returns the key and payload identifier names on a
// match; ok is false for anything that doesn't match this exact shape —
// never a partial or best-guess match.
func matchRepeatingXORGenerator(gen *tree_sitter.Node, source []byte) (keyName, payloadName string, ok bool) {
	if gen == nil || gen.Kind() != "generator_expression" || gen.NamedChildCount() != 2 {
		return "", "", false
	}
	body := gen.NamedChild(0)
	forClause := gen.NamedChild(1)
	if body == nil || forClause == nil || body.Kind() != "binary_operator" || forClause.Kind() != "for_in_clause" {
		return "", "", false
	}
	if op := body.ChildByFieldName("operator"); op == nil || op.Utf8Text(source) != "^" {
		return "", "", false
	}
	bodyVar := body.ChildByFieldName("left")
	subscript := body.ChildByFieldName("right")
	if bodyVar == nil || subscript == nil || bodyVar.Kind() != "identifier" || subscript.Kind() != "subscript" || subscript.NamedChildCount() != 2 {
		return "", "", false
	}
	keyNode := subscript.NamedChild(0)
	modExpr := subscript.NamedChild(1)
	if keyNode == nil || keyNode.Kind() != "identifier" || modExpr == nil || modExpr.Kind() != "binary_operator" {
		return "", "", false
	}
	if op := modExpr.ChildByFieldName("operator"); op == nil || op.Utf8Text(source) != "%" {
		return "", "", false
	}
	idxNode := modExpr.ChildByFieldName("left")
	lenCall := modExpr.ChildByFieldName("right")
	if idxNode == nil || idxNode.Kind() != "identifier" || lenCall == nil || lenCall.Kind() != "call" {
		return "", "", false
	}
	lenFunc := lenCall.ChildByFieldName("function")
	lenArgs := lenCall.ChildByFieldName("arguments")
	if lenFunc == nil || lenFunc.Utf8Text(source) != "len" || lenArgs == nil || lenArgs.NamedChildCount() != 1 {
		return "", "", false
	}
	if lenArg := lenArgs.NamedChild(0); lenArg == nil || lenArg.Kind() != "identifier" || lenArg.Utf8Text(source) != keyNode.Utf8Text(source) {
		return "", "", false // len(...) must reference the exact same key identifier used in the subscript
	}
	if forClause.NamedChildCount() != 2 {
		return "", "", false
	}
	patternList := forClause.NamedChild(0)
	enumerateCall := forClause.NamedChild(1)
	if patternList == nil || patternList.Kind() != "pattern_list" || patternList.NamedChildCount() != 2 {
		return "", "", false
	}
	loopIdx, loopVar := patternList.NamedChild(0), patternList.NamedChild(1)
	if loopIdx == nil || loopVar == nil || loopIdx.Kind() != "identifier" || loopVar.Kind() != "identifier" {
		return "", "", false
	}
	if loopIdx.Utf8Text(source) != idxNode.Utf8Text(source) || loopVar.Utf8Text(source) != bodyVar.Utf8Text(source) {
		return "", "", false // the for-clause's own loop variable names must match the body's exactly
	}
	if enumerateCall == nil || enumerateCall.Kind() != "call" {
		return "", "", false
	}
	enumFunc := enumerateCall.ChildByFieldName("function")
	enumArgs := enumerateCall.ChildByFieldName("arguments")
	if enumFunc == nil || enumFunc.Utf8Text(source) != "enumerate" || enumArgs == nil || enumArgs.NamedChildCount() != 1 {
		return "", "", false
	}
	payloadNode := enumArgs.NamedChild(0)
	if payloadNode == nil || payloadNode.Kind() != "identifier" {
		return "", "", false
	}
	return keyNode.Utf8Text(source), payloadNode.Utf8Text(source), true
}

// collectByteLiterals walks the whole tree for `name = b"..."` (or
// `B"..."`) module-scope assignments, last-assignment-wins (matching the
// same bounded, single-pass convention as python_ast.go's constant-
// propagation layer). Only literal Python bytes-literal assignments are
// recorded; anything else referencing the name is simply never in this
// map, so a later lookup for it correctly fails rather than resolving to
// something stale.
func collectByteLiterals(root *tree_sitter.Node, source []byte) map[string][]byte {
	literals := map[string][]byte{}
	walkXORTree(root, func(node *tree_sitter.Node) {
		if node.Kind() != "assignment" {
			return
		}
		left := node.ChildByFieldName("left")
		right := node.ChildByFieldName("right")
		if left == nil || right == nil || left.Kind() != "identifier" || right.Kind() != "string" {
			return
		}
		// string_start/string_content/string_end are positional named
		// children of a "string" node, not tree-sitter field names --
		// found by kind rather than assumed position, since a string with
		// no content at all (b"") omits the string_content child entirely.
		var startNode, contentNode *tree_sitter.Node
		for i := uint(0); i < right.NamedChildCount(); i++ {
			child := right.NamedChild(i)
			switch child.Kind() {
			case "string_start":
				startNode = child
			case "string_content":
				contentNode = child
			}
		}
		if startNode == nil {
			return
		}
		prefix := startNode.Utf8Text(source)
		if len(prefix) == 0 || (prefix[0] != 'b' && prefix[0] != 'B') {
			return // not a bytes literal (a plain str literal has no b/B prefix)
		}
		content := ""
		if contentNode != nil {
			content = contentNode.Utf8Text(source)
		}
		value, ok := unescapePythonBytesLiteral(content)
		if !ok {
			return
		}
		literals[left.Utf8Text(source)] = value
	})
	return literals
}

// unescapePythonBytesLiteral decodes the escape subset CPython actually
// recognizes inside a bytes literal: \n \t \r \\ \' \" \a \b \f \v \0 and
// \xHH (exactly two hex digits). Bytes literals do not support \uXXXX/
// \N{...} (those are str-literal-only escapes) or multi-byte non-ASCII
// source content — either raw byte >= 0x80 in the source or any escape
// sequence outside this set returns ok=false rather than guessing at a
// possibly-wrong decode.
func unescapePythonBytesLiteral(raw string) ([]byte, bool) {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		c := raw[i]
		if c != '\\' {
			if c > 0x7f {
				return nil, false
			}
			out = append(out, c)
			i++
			continue
		}
		if i+1 >= len(raw) {
			return nil, false
		}
		switch raw[i+1] {
		case 'n':
			out = append(out, '\n')
			i += 2
		case 't':
			out = append(out, '\t')
			i += 2
		case 'r':
			out = append(out, '\r')
			i += 2
		case '\\':
			out = append(out, '\\')
			i += 2
		case '\'':
			out = append(out, '\'')
			i += 2
		case '"':
			out = append(out, '"')
			i += 2
		case 'a':
			out = append(out, 0x07)
			i += 2
		case 'b':
			out = append(out, 0x08)
			i += 2
		case 'f':
			out = append(out, 0x0c)
			i += 2
		case 'v':
			out = append(out, 0x0b)
			i += 2
		case '0':
			out = append(out, 0x00)
			i += 2
		case 'x':
			if i+4 > len(raw) {
				return nil, false
			}
			value, err := strconv.ParseUint(raw[i+2:i+4], 16, 8)
			if err != nil {
				return nil, false
			}
			out = append(out, byte(value))
			i += 4
		default:
			return nil, false
		}
	}
	return out, true
}

func walkXORTree(node *tree_sitter.Node, visit func(*tree_sitter.Node)) {
	if node == nil {
		return
	}
	visit(node)
	for i := uint(0); i < node.NamedChildCount(); i++ {
		walkXORTree(node.NamedChild(i), visit)
	}
}
