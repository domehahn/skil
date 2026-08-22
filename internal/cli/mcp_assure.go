package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/eval"
	"github.com/domehahn/skil/internal/mcpassure"
)

// mcpAssuranceResult is the JSON shape for `skil mcp assure`. Field names
// mirror assuranceResult's conventions (schema_version, artifact_digest)
// for consistency across skil's assurance-family commands.
type mcpAssuranceResult struct {
	SchemaVersion     string                      `json:"schema_version"`
	Passed            bool                        `json:"passed"`
	ArtifactDigest    string                      `json:"artifact_digest"`
	ProtocolVersion   string                      `json:"protocol_version"`
	ServerName        string                      `json:"server_name"`
	ServerVersion     string                      `json:"server_version"`
	ToolsObserved     int                         `json:"tools_observed"`
	Mismatches        []mcpassure.Mismatch        `json:"mismatches"`
	SurfaceMismatches []mcpassure.SurfaceMismatch `json:"surface_mismatches,omitempty"`
}

func (a *App) mcpAssure(ctx context.Context, args []string) int {
	fs := newFlags("mcp assure", a.Err)
	runtimeCommand := fs.String("runtime-command", "", "executable for the MCP server to launch and observe")
	runtimeArgs := fs.String("runtime-args", "", "comma-separated MCP server arguments")
	timeout := fs.Duration("timeout", mcpassure.DefaultTimeout, "per-request MCP handshake timeout")
	maxResponseBytes := fs.Int64("max-response-bytes", mcpassure.DefaultMaxResponseBytes, "maximum size of a single MCP response frame")
	format := fs.String("format", "terminal", "terminal or json")
	output := fs.String("output", "", "assurance result output")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if strings.TrimSpace(*runtimeCommand) == "" {
		return a.inputError(errors.New("mcp assure requires --runtime-command for the MCP server to launch and observe; skil never executes an artifact-declared command on its own"))
	}
	if *format != "terminal" && *format != "json" {
		return a.inputError(errors.New("mcp assure supports terminal or json output"))
	}

	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	lock, err := analyzer.LoadMCPLock(art)
	if err != nil {
		return a.inputError(err)
	}
	surfaceLock, err := mcpassure.LoadSurfaceLock(art)
	if err != nil {
		return a.inputError(err)
	}
	if len(lock) == 0 && surfaceLock.Version == 0 {
		return a.inputError(errors.New("mcp assure requires .skil/mcp-tools.lock.json or .skil/mcp-surface.lock.json; dynamic assurance has nothing reviewed to compare against otherwise"))
	}

	isolation, err := eval.NewNativeIsolation()
	if err != nil {
		return a.internalError(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, *timeout*10) // overall ceiling; per-request bound is *timeout
	defer cancel()
	result, err := mcpassure.Run(runCtx, isolation, mcpassure.RunRequest{
		Executable: *runtimeCommand, Args: splitNonEmpty(*runtimeArgs),
		Options: mcpassure.Options{Timeout: *timeout, MaxResponseBytes: *maxResponseBytes},
	}, lock)
	if err != nil {
		return a.internalError(fmt.Errorf("dynamic MCP assurance: %w", err))
	}
	if len(lock) == 0 {
		// mcpassure.Run always compares against lock even when empty,
		// which would otherwise flag every observed tool as "undeclared"
		// under SKIL-MCP-011/mcp-tools.lock.json even though the operator
		// deliberately maintains only the surface lock and never intended
		// a v1 comparison to run at all.
		result.Mismatches = nil
	}
	surfaceMismatches, err := mcpassure.CompareSurfaceToLock(result.Discovery, surfaceLock)
	if err != nil {
		return a.internalError(fmt.Errorf("MCP surface comparison: %w", err))
	}

	assurance := mcpAssuranceResult{
		SchemaVersion: "1.0.0", Passed: result.Passed() && len(surfaceMismatches) == 0, ArtifactDigest: art.SubjectDigest(),
		ProtocolVersion: result.Discovery.ProtocolVersion, ServerName: result.Discovery.ServerName,
		ServerVersion: result.Discovery.ServerVersion, ToolsObserved: len(result.Discovery.Tools),
		Mismatches: result.Mismatches, SurfaceMismatches: surfaceMismatches,
	}
	if assurance.Mismatches == nil {
		assurance.Mismatches = []mcpassure.Mismatch{}
	}

	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if *format == "json" {
		err = writeJSON(writer, assurance)
	} else {
		err = writeMCPAssuranceTerminal(writer, assurance)
	}
	if err != nil {
		return a.internalError(err)
	}
	if !assurance.Passed {
		return ExitGateFail
	}
	return ExitOK
}

func writeMCPAssuranceTerminal(writer io.Writer, result mcpAssuranceResult) error {
	if _, err := fmt.Fprintf(writer, "DYNAMIC MCP ASSURANCE\n\nArtifact digest: sha256:%s\nServer:          %s %s (protocol %s)\nTools observed:  %d\nResult:          %s\n",
		result.ArtifactDigest, result.ServerName, result.ServerVersion, result.ProtocolVersion,
		result.ToolsObserved, map[bool]string{true: "PASS", false: "FAIL"}[result.Passed]); err != nil {
		return err
	}
	if len(result.Mismatches) == 0 && len(result.SurfaceMismatches) == 0 {
		_, err := fmt.Fprintln(writer, "\nEvery observed tool/prompt/resource's live metadata matches the reviewed lock(s).")
		return err
	}
	if len(result.Mismatches) > 0 {
		if _, err := fmt.Fprintf(writer, "\nMismatches (%d)\n", len(result.Mismatches)); err != nil {
			return err
		}
		for _, mismatch := range result.Mismatches {
			switch mismatch.Kind {
			case mcpassure.MismatchUndeclared:
				if _, err := fmt.Fprintf(writer, "- [SKIL-MCP-011] %s: observed at runtime but not declared in .skil/mcp-tools.lock.json (sha256:%s)\n",
					mismatch.Tool, mismatch.ObservedDescSHA256); err != nil {
					return err
				}
			case mcpassure.MismatchDigest:
				if _, err := fmt.Fprintf(writer, "- [SKIL-MCP-011] %s: live description does not match the reviewed lock (expected sha256:%s, observed sha256:%s)\n",
					mismatch.Tool, mismatch.ExpectedDescSHA256, mismatch.ObservedDescSHA256); err != nil {
					return err
				}
			}
		}
	}
	if len(result.SurfaceMismatches) > 0 {
		if _, err := fmt.Fprintf(writer, "\nSurface mismatches (%d)\n", len(result.SurfaceMismatches)); err != nil {
			return err
		}
		for _, mismatch := range result.SurfaceMismatches {
			label := mismatch.Component
			if mismatch.Name != "" {
				label += " " + mismatch.Name
			}
			switch mismatch.Kind {
			case mcpassure.SurfaceMismatchUndeclared:
				if _, err := fmt.Fprintf(writer, "- [SKIL-MCP-012] %s: observed at runtime but not declared in .skil/mcp-surface.lock.json (sha256:%s)\n",
					label, mismatch.ObservedSHA256); err != nil {
					return err
				}
			case mcpassure.SurfaceMismatchDigest:
				if _, err := fmt.Fprintf(writer, "- [SKIL-MCP-012] %s: live object does not match the reviewed surface lock (expected sha256:%s, observed sha256:%s)\n",
					label, mismatch.ExpectedSHA256, mismatch.ObservedSHA256); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
