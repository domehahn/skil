package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/domehahn/skil/internal/mcpregistry"
)

func (a *App) mcpRegistry(ctx context.Context, args []string) int {
	if len(args) < 2 || args[0] != "registry" || args[1] != "scan" {
		return a.inputError(errors.New("usage: skil mcp registry scan [file|server-name] [--official] [--format terminal|json]"))
	}
	fs := newFlags("mcp registry scan", a.Err)
	official := fs.Bool("official", false, "fetch from the official MCP Registry v0.1 API")
	format := fs.String("format", "terminal", "terminal or json")
	output := fs.String("output", "", "write the report to a file")
	expectedDigest := fs.String("expected-record-sha256", "", "expected canonical SHA-256 for a single registry record")
	closurePath := fs.String("reviewed-closure", "", "JSON or YAML skill contract containing reviewed_closure")
	baselinePath := fs.String("baseline", "", "previous local registry snapshot used to detect repository ownership changes")
	if err := fs.Parse(interspersed(fs, args[2:])); err != nil {
		return ExitInput
	}
	if *format != "terminal" && *format != "json" {
		return a.inputError(errors.New("MCP registry scan supports terminal or json output"))
	}
	if (!*official && fs.NArg() != 1) || (*official && fs.NArg() > 1) {
		return a.inputError(errors.New("local scans require one file; --official accepts an optional namespace/name"))
	}

	options := mcpregistry.Options{Official: *official, ExpectedRecordSHA256: *expectedDigest}
	if *closurePath != "" {
		data, err := readMCPRegistryFile(*closurePath)
		if err != nil {
			return a.inputError(fmt.Errorf("read reviewed closure: %w", err))
		}
		options.ReviewedClosure, err = mcpregistry.ParseReviewedClosure(data)
		if err != nil {
			return a.inputError(fmt.Errorf("parse reviewed closure: %w", err))
		}
	}
	if *baselinePath != "" {
		data, err := readMCPRegistryFile(*baselinePath)
		if err != nil {
			return a.inputError(fmt.Errorf("read baseline: %w", err))
		}
		options.BaselineRepositories, err = mcpregistry.BaselineRepositories(data)
		if err != nil {
			return a.inputError(fmt.Errorf("parse baseline: %w", err))
		}
	}

	var data []byte
	var source string
	var err error
	if *official {
		serverName := ""
		if fs.NArg() == 1 {
			serverName = fs.Arg(0)
		}
		data, source, options.LatestEndpoint, err = mcpregistry.FetchOfficial(ctx, serverName, nil)
	} else {
		source = fs.Arg(0)
		data, err = readMCPRegistryFile(source)
	}
	if err != nil {
		return a.inputError(err)
	}
	if !*official && *output != "" && sameMCPRegistryPath(source, *output) {
		return a.inputError(errors.New("MCP registry output must not overwrite its input"))
	}
	report, err := mcpregistry.Scan(source, data, options)
	if err != nil {
		return a.inputError(err)
	}

	writer, closeWriter, err := mcpRegistryWriter(*output, a.Out)
	if err != nil {
		return a.inputError(err)
	}
	defer closeWriter()
	if *format == "json" {
		err = writeJSON(writer, report)
	} else {
		err = writeMCPRegistryTerminal(writer, report)
	}
	if err != nil {
		return a.internalError(err)
	}
	if report.Summary.Passed {
		return ExitOK
	}
	return ExitGateFail
}

func sameMCPRegistryPath(left, right string) bool {
	leftAbsolute, leftErr := filepath.Abs(left)
	rightAbsolute, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && filepath.Clean(leftAbsolute) == filepath.Clean(rightAbsolute)
}

func readMCPRegistryFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("MCP registry input must be a regular non-symlink file")
	}
	if info.Size() > mcpregistry.MaxDocumentBytes {
		return nil, fmt.Errorf("MCP registry input exceeds %d bytes", mcpregistry.MaxDocumentBytes)
	}
	return os.ReadFile(path)
}

func mcpRegistryWriter(path string, fallback io.Writer) (io.Writer, func(), error) {
	if path == "" {
		return fallback, func() {}, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, func() {}, err
	}
	file, err := os.OpenFile(absolute, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { _ = file.Close() }, nil
}

func writeMCPRegistryTerminal(writer io.Writer, report mcpregistry.Report) error {
	if _, err := fmt.Fprintf(writer, "MCP REGISTRY POSTURE\n\nSource:  %s\nDigest:  sha256:%s\nRecords: %d\nResult:  %s\n",
		report.Source, report.SourceSHA256, report.Summary.Records, map[bool]string{true: "PASS", false: "FAIL"}[report.Summary.Passed]); err != nil {
		return err
	}
	if len(report.Findings) == 0 {
		_, err := fmt.Fprintln(writer, "\nNo posture findings.")
		return err
	}
	if _, err := fmt.Fprintf(writer, "\nFindings (%d)\n", len(report.Findings)); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		location := strings.Trim(strings.Join([]string{finding.Record, finding.Field}, " "), " ")
		if _, err := fmt.Fprintf(writer, "- [%s] %s %s: %s\n", finding.Severity, finding.Code, location, finding.Message); err != nil {
			return err
		}
	}
	return nil
}
