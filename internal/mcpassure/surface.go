package mcpassure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
	"github.com/domehahn/skil/schemas"
)

// MCP Surface Lock v2: unlike the description-only mcp-tools.lock.json
// (SKIL-MCP-005/SKIL-MCP-011), each entry in .skil/mcp-surface.lock.json
// is a canonical-JSON digest of an entire reviewed live object — a tool's
// name, description, AND input schema; a prompt's name and description; a
// resource's uri, name, and description; and the server's own name,
// version, and protocol version. A rug pull that keeps a tool's
// description unchanged but alters its input schema (or an MCP server
// that swaps its declared identity) is invisible to the tools-only lock
// but not to this one.
//
// This is deliberately a separate lock file and separate rule ID
// (SKIL-MCP-012) from the existing mcp-tools.lock.json/SKIL-MCP-011 pair,
// not a replacement or a breaking change to either — an operator adopts
// mcp-surface.lock.json when ready, and both locks can coexist.
//
// Scope: outputSchema, annotations, and resource mimeType are not yet
// part of the canonical object hashed here (Tool/Prompt/Resource in
// client.go do not parse them) — a natural future extension once real
// demand for it appears, not included in this first pass.

// SurfaceLock is the parsed, validated .skil/mcp-surface.lock.json.
type SurfaceLock struct {
	Version      int               `json:"version"`
	ServerSHA256 string            `json:"server_sha256,omitempty"`
	Tools        map[string]string `json:"tools,omitempty"`
	Prompts      map[string]string `json:"prompts,omitempty"`
	Resources    map[string]string `json:"resources,omitempty"`
}

// LoadSurfaceLock parses and validates .skil/mcp-surface.lock.json if
// present. A missing file returns a zero-value SurfaceLock and no error —
// exactly like LoadMCPLock's own convention for the absent-lock case.
func LoadSurfaceLock(artifact skil.Artifact) (SurfaceLock, error) {
	for _, file := range artifact.Files {
		if file.Path != ".skil/mcp-surface.lock.json" {
			continue
		}
		if err := schemas.ValidateYAML("mcp-surface-lock-v1.schema.json", file.Data); err != nil {
			return SurfaceLock{}, fmt.Errorf("validate MCP surface lock: %w", err)
		}
		var lock SurfaceLock
		decoder := json.NewDecoder(strings.NewReader(string(file.Data)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&lock); err != nil {
			return SurfaceLock{}, fmt.Errorf("parse MCP surface lock: %w", err)
		}
		if lock.Version != 1 {
			return SurfaceLock{}, fmt.Errorf("MCP surface lock requires version 1")
		}
		for _, digests := range []map[string]string{lock.Tools, lock.Prompts, lock.Resources} {
			for name, digest := range digests {
				if err := validateSurfaceDigest(name, digest); err != nil {
					return SurfaceLock{}, err
				}
			}
		}
		if lock.ServerSHA256 != "" {
			if err := validateSurfaceDigest("server_sha256", lock.ServerSHA256); err != nil {
				return SurfaceLock{}, err
			}
		}
		return lock, nil
	}
	return SurfaceLock{}, nil
}

func (l SurfaceLock) empty() bool {
	return l.Version == 0 && l.ServerSHA256 == "" && len(l.Tools) == 0 && len(l.Prompts) == 0 && len(l.Resources) == 0
}

func validateSurfaceDigest(name, digest string) error {
	if strings.TrimSpace(name) == "" || len(digest) != 64 {
		return fmt.Errorf("MCP surface lock contains an invalid entry or digest")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("MCP surface lock contains a non-hex digest")
	}
	return nil
}

// canonicalObjectDigest hashes v's canonical JSON form (recursively
// key-sorted — see internal/signing.CanonicalJSON, the same
// canonicalization skil's own signing/attestation layer uses) so the
// digest is independent of struct field declaration order or incidental
// map iteration order.
func canonicalObjectDigest(v any) (string, error) {
	data, err := signing.CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func serverDigest(discovery Discovery) (string, error) {
	return canonicalObjectDigest(struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		ProtocolVersion string `json:"protocol_version"`
	}{discovery.ServerName, discovery.ServerVersion, discovery.ProtocolVersion})
}

func toolDigest(tool Tool) (string, error) {
	return canonicalObjectDigest(struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema,omitempty"`
	}{tool.Name, tool.Description, tool.InputSchema})
}

func promptDigest(prompt Prompt) (string, error) {
	return canonicalObjectDigest(struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}{prompt.Name, prompt.Description})
}

func resourceDigest(resource Resource) (string, error) {
	return canonicalObjectDigest(struct {
		URI         string `json:"uri"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}{resource.URI, resource.Name, resource.Description})
}

// SurfaceMismatchKind mirrors MismatchKind's two cases for the broader
// full-surface comparison.
type SurfaceMismatchKind string

const (
	SurfaceMismatchUndeclared SurfaceMismatchKind = "undeclared"
	SurfaceMismatchDigest     SurfaceMismatchKind = "digest_mismatch"
)

// SurfaceMismatch is one component (the server itself, a tool, a prompt,
// or a resource) whose live, dynamically-observed full object disagrees
// with — or was never declared in — the surface lock.
type SurfaceMismatch struct {
	Component      string // "server", "tool", "prompt", or "resource"
	Name           string // tool/prompt name, resource URI; empty for "server"
	Kind           SurfaceMismatchKind
	ExpectedSHA256 string
	ObservedSHA256 string
}

// CompareSurfaceToLock hashes the server identity and every observed
// tool/prompt/resource's full canonical object and reports every
// component whose live metadata disagrees with lock, or that was never
// declared in it. An empty lock (no file present) yields no mismatches —
// a caller with only mcp-tools.lock.json and no surface lock yet simply
// gets no surface-level comparison, not a spurious "everything is
// undeclared" result.
func CompareSurfaceToLock(discovery Discovery, lock SurfaceLock) ([]SurfaceMismatch, error) {
	if lock.empty() {
		return nil, nil
	}
	var mismatches []SurfaceMismatch

	if lock.ServerSHA256 != "" {
		observed, err := serverDigest(discovery)
		if err != nil {
			return nil, fmt.Errorf("hash server identity: %w", err)
		}
		if observed != lock.ServerSHA256 {
			mismatches = append(mismatches, SurfaceMismatch{
				Component: "server", Kind: SurfaceMismatchDigest,
				ExpectedSHA256: lock.ServerSHA256, ObservedSHA256: observed,
			})
		}
	}
	for _, tool := range discovery.Tools {
		observed, err := toolDigest(tool)
		if err != nil {
			return nil, fmt.Errorf("hash tool %q: %w", tool.Name, err)
		}
		mismatches = append(mismatches, surfaceEntryMismatch("tool", tool.Name, observed, lock.Tools)...)
	}
	for _, prompt := range discovery.Prompts {
		observed, err := promptDigest(prompt)
		if err != nil {
			return nil, fmt.Errorf("hash prompt %q: %w", prompt.Name, err)
		}
		mismatches = append(mismatches, surfaceEntryMismatch("prompt", prompt.Name, observed, lock.Prompts)...)
	}
	for _, resource := range discovery.Resources {
		observed, err := resourceDigest(resource)
		if err != nil {
			return nil, fmt.Errorf("hash resource %q: %w", resource.URI, err)
		}
		mismatches = append(mismatches, surfaceEntryMismatch("resource", resource.URI, observed, lock.Resources)...)
	}
	return mismatches, nil
}

func surfaceEntryMismatch(component, name, observed string, locked map[string]string) []SurfaceMismatch {
	expected, declared := locked[name]
	switch {
	case !declared:
		return []SurfaceMismatch{{Component: component, Name: name, Kind: SurfaceMismatchUndeclared, ObservedSHA256: observed}}
	case observed != expected:
		return []SurfaceMismatch{{Component: component, Name: name, Kind: SurfaceMismatchDigest, ExpectedSHA256: expected, ObservedSHA256: observed}}
	default:
		return nil
	}
}
