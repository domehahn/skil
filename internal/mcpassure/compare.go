package mcpassure

import (
	"crypto/sha256"
	"encoding/hex"
)

// MismatchKind distinguishes an undeclared runtime tool from a rug-pulled
// one so callers can report and remediate each correctly.
type MismatchKind string

const (
	// MismatchUndeclared means the server exposed a tool at runtime that
	// has no entry at all in .skil/mcp-tools.lock.json — either the lock
	// is stale, or the server is offering something never reviewed.
	MismatchUndeclared MismatchKind = "undeclared"
	// MismatchDigest means the tool is in the lock, but the description
	// observed live over the wire hashes to something other than the
	// locked digest — the runtime rug pull static manifest parsing alone
	// cannot see, since a manifest file can say one thing while the
	// server says another.
	MismatchDigest MismatchKind = "digest_mismatch"
)

// Mismatch is one tool whose live, dynamically-observed metadata disagrees
// with the reviewed, locked metadata.
type Mismatch struct {
	Tool               string
	Kind               MismatchKind
	ExpectedDescSHA256 string
	ObservedDescSHA256 string
}

// CompareToLock hashes each dynamically-observed tool's description with
// the exact same convention SKIL-MCP-005 already uses for static manifest
// comparison (hex(sha256(description)), no normalization — see
// internal/analyzer.LoadMCPLock) and reports every tool whose live metadata
// disagrees with the lock. Tools present in the lock but not observed at
// runtime are not reported here — that is a separate, weaker signal (the
// server may simply not enable every locked tool in this configuration)
// left to the caller to decide whether it matters.
func CompareToLock(discovery Discovery, lock map[string]string) []Mismatch {
	var mismatches []Mismatch
	for _, tool := range discovery.Tools {
		sum := sha256.Sum256([]byte(tool.Description))
		observed := hex.EncodeToString(sum[:])
		expected, declared := lock[tool.Name]
		switch {
		case !declared:
			mismatches = append(mismatches, Mismatch{
				Tool: tool.Name, Kind: MismatchUndeclared, ObservedDescSHA256: observed,
			})
		case observed != expected:
			mismatches = append(mismatches, Mismatch{
				Tool: tool.Name, Kind: MismatchDigest,
				ExpectedDescSHA256: expected, ObservedDescSHA256: observed,
			})
		}
	}
	return mismatches
}
