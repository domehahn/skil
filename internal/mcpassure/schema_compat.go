package mcpassure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/domehahn/skil/internal/completeness"
	"github.com/domehahn/skil/internal/signing"
)

// NormalizeToolPayload accepts MCP tool descriptors using either camelCase
// (inputSchema, outputSchema) or snake_case (input_schema, output_schema) wire
// conventions, rejecting conflicting dual definitions and returning a unified Tool.
func NormalizeToolPayload(raw []byte) (Tool, error) {
	var wire map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&wire); err != nil {
		return Tool{}, fmt.Errorf("decode MCP tool descriptor: %w", err)
	}
	var name, desc string
	if rawName, ok := wire["name"]; ok {
		if err := json.Unmarshal(rawName, &name); err != nil {
			return Tool{}, fmt.Errorf("invalid MCP tool name: %w", err)
		}
	}
	if strings.TrimSpace(name) == "" {
		return Tool{}, errors.New("MCP tool descriptor requires non-empty name")
	}
	if rawDesc, ok := wire["description"]; ok {
		_ = json.Unmarshal(rawDesc, &desc)
	}

	pickSchema := func(camel, snake string) (json.RawMessage, error) {
		cVal, cOK := wire[camel]
		sVal, sOK := wire[snake]
		if cOK && sOK {
			cCanon, err1 := signing.CanonicalJSON(cVal)
			sCanon, err2 := signing.CanonicalJSON(sVal)
			if err1 != nil || err2 != nil || string(cCanon) != string(sCanon) {
				return nil, fmt.Errorf("conflicting %s and %s in MCP tool %q", camel, snake, name)
			}
		}
		if cOK && len(cVal) > 0 && string(cVal) != "null" {
			canon, err := signing.CanonicalJSON(cVal)
			if err != nil {
				return nil, err
			}
			return json.RawMessage(canon), nil
		}
		if sOK && len(sVal) > 0 && string(sVal) != "null" {
			canon, err := signing.CanonicalJSON(sVal)
			if err != nil {
				return nil, err
			}
			return json.RawMessage(canon), nil
		}
		return nil, nil
	}

	inSchema, err := pickSchema("inputSchema", "input_schema")
	if err != nil {
		return Tool{}, err
	}
	outSchema, err := pickSchema("outputSchema", "output_schema")
	if err != nil {
		return Tool{}, err
	}
	var annotations json.RawMessage
	if rawAnn, ok := wire["annotations"]; ok && len(rawAnn) > 0 && string(rawAnn) != "null" {
		canon, err := signing.CanonicalJSON(rawAnn)
		if err != nil {
			return Tool{}, err
		}
		annotations = json.RawMessage(canon)
	}
	return Tool{
		Name:         name,
		Description:  desc,
		InputSchema:  inSchema,
		OutputSchema: outSchema,
		Annotations:  annotations,
	}, nil
}

// BinaryExecutionIdentity distinguishes a bare command basename ("python",
// "printf", "env", "npx") from a resolved, digest-pinned binary target.
// Basename-only resolution is never classified as EXACT.
type BinaryExecutionIdentity struct {
	DeclaredCommand   string                       `json:"declared_command"`
	DeclaredBasename  string                       `json:"declared_basename"`
	ResolvedPath      string                       `json:"resolved_path,omitempty"`
	SymlinkTargetPath string                       `json:"symlink_target_path,omitempty"`
	ExecutableSHA256  string                       `json:"executable_sha256,omitempty"`
	WrapperKind       string                       `json:"wrapper_kind,omitempty"`
	Interpreter       string                       `json:"interpreter,omitempty"`
	ResolutionState   completeness.ResolutionState `json:"resolution_state"`
	LimitationReason  string                       `json:"limitation_reason,omitempty"`
}

var dynamicCommandWrappers = map[string]bool{
	"env": true, "command": true, "builtin": true, "nohup": true, "exec": true,
	"xargs": true, "sudo": true, "doas": true, "npx": true, "uvx": true, "pipx": true,
}

var pathDependentBuiltins = map[string]bool{
	"printf": true, "echo": true, "test": true, "[": true, "kill": true, "pwd": true, "time": true,
}

// ClassifyBinaryIdentity evaluates how accurately an execution target can be
// bound prior to runtime execution.
func ClassifyBinaryIdentity(declaredCmd, resolvedPath, symlinkTarget, sha256Hex string) BinaryExecutionIdentity {
	fields := strings.Fields(strings.TrimSpace(declaredCmd))
	if len(fields) == 0 {
		return BinaryExecutionIdentity{
			ResolutionState:  completeness.StateRuntimeUnknown,
			LimitationReason: "empty command declaration",
		}
	}
	first := fields[0]
	base := filepath.Base(first)
	id := BinaryExecutionIdentity{
		DeclaredCommand:   declaredCmd,
		DeclaredBasename:  base,
		ResolvedPath:      strings.TrimSpace(resolvedPath),
		SymlinkTargetPath: strings.TrimSpace(symlinkTarget),
		ExecutableSHA256:  strings.TrimSpace(sha256Hex),
	}

	if dynamicCommandWrappers[base] {
		id.WrapperKind = base
		id.ResolutionState = completeness.StateRuntimeUnknown
		id.LimitationReason = fmt.Sprintf("wrapper %q selects or mutates the effective executable at runtime", base)
		return id
	}
	if pathDependentBuiltins[base] && !filepath.IsAbs(first) && id.ResolvedPath == "" {
		id.ResolutionState = completeness.StatePartial
		id.LimitationReason = fmt.Sprintf("%q may resolve to a shell builtin or PATH binary depending on runtime shell", base)
		return id
	}
	if !filepath.IsAbs(first) && id.ResolvedPath == "" {
		id.ResolutionState = completeness.StatePartial
		id.LimitationReason = "basename-only command depends on runtime PATH resolution"
		return id
	}
	if id.ExecutableSHA256 == "" {
		id.ResolutionState = completeness.StatePartial
		id.LimitationReason = "executable path resolved without immutable content SHA-256 digest"
		return id
	}
	if len(id.ExecutableSHA256) != 64 {
		if _, err := hex.DecodeString(strings.TrimPrefix(id.ExecutableSHA256, "sha256:")); err != nil {
			id.ResolutionState = completeness.StatePartial
			id.LimitationReason = "executable digest is not a valid SHA-256 hex digest"
			return id
		}
	}
	id.ResolutionState = completeness.StateExact
	return id
}

// ComputeBinaryIdentityDigest returns a deterministic digest over the binary identity.
func (b BinaryExecutionIdentity) ComputeDigest() string {
	raw, _ := signing.CanonicalJSON(b)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
