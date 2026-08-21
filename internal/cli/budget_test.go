package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestScanReportsAnalysisBudgetAndFailOnIncompleteIsANoOpWhenWithinBudget(t *testing.T) {
	var out, errOut bytes.Buffer
	code := New(&out, &errOut).Run(context.Background(), []string{
		"scan", fixture(t, "clean-skill"), "--static-only", "--fail-on-incomplete", "--format", "json",
	})
	if code != ExitOK {
		t.Fatalf("an ordinary clean scan within budget must still pass with --fail-on-incomplete: code=%d stderr=%s", code, errOut.String())
	}
	var result struct {
		AnalysisBudget struct {
			Exceeded []string `json:"exceeded"`
			RawBytes struct {
				Limit int64 `json:"limit"`
			} `json:"raw_bytes"`
		} `json:"analysis_budget"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("parse scan JSON output: %v\n%s", err, out.String())
	}
	if len(result.AnalysisBudget.Exceeded) != 0 {
		t.Fatalf("expected no exceeded budget dimensions for a small clean fixture: %#v", result.AnalysisBudget)
	}
	if result.AnalysisBudget.RawBytes.Limit == 0 {
		t.Fatalf("expected the analysis_budget field to report a non-zero raw_bytes limit: %#v", result.AnalysisBudget)
	}
}
