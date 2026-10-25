package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunCompleteness_Terminal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "skil-completeness-cli-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	var out, errOut bytes.Buffer
	code := RunCompleteness([]string{tmpDir, "--format=terminal"}, &out, &errOut)

	if code != ExitOK {
		t.Fatalf("RunCompleteness failed with code %d, stderr: %s", code, errOut.String())
	}

	output := out.String()
	if !strings.Contains(output, "SKIL Assurance Completeness Report") {
		t.Errorf("Expected output to contain header, got:\n%s", output)
	}

	if !strings.Contains(output, "Work Accounting Ledger") {
		t.Errorf("Expected output to contain Work Accounting Ledger section")
	}
}

func TestRunCompleteness_JSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "skil-completeness-cli-json-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	var out, errOut bytes.Buffer
	code := RunCompleteness([]string{tmpDir, "--format=json"}, &out, &errOut)

	if code != ExitOK {
		t.Fatalf("RunCompleteness failed with code %d, stderr: %s", code, errOut.String())
	}

	output := out.String()
	if !strings.Contains(output, `"classification"`) || !strings.Contains(output, `"work_ledger"`) {
		t.Errorf("Expected valid JSON output, got:\n%s", output)
	}
}
