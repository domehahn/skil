package cli

import (
	"bytes"
	"context"
	"flag"
	"strings"
	"testing"
)

// buildAnalysisFlags mirrors how each command's flag set is normally
// built, so analysisRegistry can be exercised directly without a full
// Scan (which would need a real semantic provider network call).
func buildAnalysisFlags(t *testing.T, args ...string) analysisFlags {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags := bindAnalysisFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	return flags
}

func TestSemanticRunsRejectsLessThanOne(t *testing.T) {
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	flags := buildAnalysisFlags(t, "--semantic", "--semantic-model", "x", "--semantic-runs", "0")
	if _, err := app.analysisRegistry(context.Background(), flags); err == nil || !strings.Contains(err.Error(), "--semantic-runs must be at least 1") {
		t.Fatalf("expected a --semantic-runs validation error, got %v", err)
	}
}

func TestSemanticRunsAboveOneWrapsProviderWithConsensusAndLogs(t *testing.T) {
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	flags := buildAnalysisFlags(t, "--semantic", "--semantic-model", "x", "--semantic-runs", "5")
	registry, err := app.analysisRegistry(context.Background(), flags)
	if err != nil {
		t.Fatalf("expected consensus-wrapped registry construction to succeed without any network call: %v", err)
	}
	if registry == nil {
		t.Fatal("expected a non-nil registry")
	}
	if !strings.Contains(errOut.String(), "semantic multi-run consensus: 5 independent passes") {
		t.Fatalf("expected a consensus log line, got stderr=%s", errOut.String())
	}
}

func TestSemanticRunsOfOneDoesNotLogConsensus(t *testing.T) {
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	flags := buildAnalysisFlags(t, "--semantic", "--semantic-model", "x")
	if _, err := app.analysisRegistry(context.Background(), flags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(errOut.String(), "consensus") {
		t.Fatalf("default --semantic-runs=1 must not mention consensus, got stderr=%s", errOut.String())
	}
}
