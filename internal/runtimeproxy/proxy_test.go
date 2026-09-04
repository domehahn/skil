package runtimeproxy

import (
	"context"
	"testing"
)

func TestEvaluateToolCall_AllowAndRedact(t *testing.T) {
	ctx := context.Background()
	policy := DefaultProxyPolicy()

	req := ToolCallRequest{
		ToolName: "fetch_url",
		Arguments: map[string]interface{}{
			"url":    "https://api.github.com/repos/domehahn/skil",
			"secret": "token=ghp_1234567890abcdefghijklmnopqrst",
		},
	}

	resp := EvaluateToolCall(ctx, req, policy)
	if resp.Decision == DecisionBlock {
		t.Fatalf("expected call to be allowed/redacted, got blocked: %s", resp.Reason)
	}

	secretArg, _ := resp.SanitizedArguments["secret"].(string)
	if secretArg == "token=ghp_1234567890abcdefghijklmnopqrst" {
		t.Errorf("expected secret to be redacted, got original string")
	}
}

func TestEvaluateToolCall_BlockForbiddenCommand(t *testing.T) {
	ctx := context.Background()
	policy := DefaultProxyPolicy()

	req := ToolCallRequest{
		ToolName: "execute_command",
		Arguments: map[string]interface{}{
			"command": "sudo rm -rf /",
		},
	}

	resp := EvaluateToolCall(ctx, req, policy)
	if resp.Decision != DecisionBlock {
		t.Fatalf("expected forbidden command to be BLOCKED, got decision %s", resp.Decision)
	}
}
