package external

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestMockExternalProvider(t *testing.T) {
	mock := &MockExternalProvider{
		ProviderName: "semgrep-adapter",
		MockFindings: []skil.Finding{
			NormalizedExternalFinding("semgrep", "python-eval", "security", skil.SeverityHigh, 0.9, "Dynamic Eval", "eval() call found", "main.py", 10),
		},
		MockLift:    0.18,
		MockPassAtK: 0.90,
	}

	if mock.Name() != "semgrep-adapter" {
		t.Errorf("Expected name semgrep-adapter, got %s", mock.Name())
	}

	findings, err := mock.Scan(context.Background(), &skil.Artifact{})
	if err != nil || len(findings) != 1 {
		t.Fatalf("Expected 1 finding from mock scan, got %d (err: %v)", len(findings), err)
	}

	if findings[0].RuleID != "semgrep-python-eval" {
		t.Errorf("Expected RuleID semgrep-python-eval, got %s", findings[0].RuleID)
	}

	lift, passAtK, err := mock.Evaluate(context.Background(), &skil.Artifact{})
	if err != nil || lift != 0.18 || passAtK != 0.90 {
		t.Fatalf("Expected lift 0.18 & passAtK 0.90, got lift %.2f passAtK %.2f", lift, passAtK)
	}
}
