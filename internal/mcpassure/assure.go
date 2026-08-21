package mcpassure

import (
	"context"
	"fmt"

	"github.com/domehahn/skil/internal/eval"
)

// RunRequest describes the operator-supplied MCP server command to launch
// and observe. Executable is mandatory and never inferred from the
// artifact: skil does not execute an artifact-declared command on its own,
// mirroring skil assure's own --runtime-command requirement.
type RunRequest struct {
	Executable  string
	Args        []string
	Environment []string
	Options     Options
}

// Result is the full outcome of one dynamic assurance run: what the
// server declared live, and how that compares to the reviewed lock.
type Result struct {
	Discovery  Discovery
	Mismatches []Mismatch
}

// Passed reports whether the run found zero mismatches against the lock.
// A lock with no tools (empty map) makes every observed tool "undeclared"
// — dynamic assurance without a lock can observe, but has nothing to
// assure against, and callers should treat that as a configuration
// problem rather than a clean pass.
func (r Result) Passed() bool { return len(r.Mismatches) == 0 }

// Run launches request.Executable inside skil's sandboxed streaming
// isolation, performs the live MCP handshake, and compares the result
// against lock (as produced by internal/analyzer.LoadMCPLock). The
// isolation provider must support streaming (internal/eval.NativeIsolation
// does on darwin/linux/windows); a plain IsolationProvider that only
// implements the one-shot Run/RunWithLimits batch model cannot drive this
// protocol's multi-round-trip handshake.
func Run(ctx context.Context, provider eval.StreamingIsolationProvider, request RunRequest, lock map[string]string) (Result, error) {
	session, err := provider.Start(ctx, eval.IsolationRequest{
		Executable:  request.Executable,
		Args:        request.Args,
		Environment: request.Environment,
	})
	if err != nil {
		return Result{}, fmt.Errorf("start sandboxed mcp server: %w", err)
	}
	defer session.Close()

	discovery, err := Discover(ctx, session, request.Options)
	if err != nil {
		return Result{}, fmt.Errorf("mcp handshake: %w", err)
	}
	return Result{Discovery: discovery, Mismatches: CompareToLock(discovery, lock)}, nil
}
