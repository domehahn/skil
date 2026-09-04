package runtimeproxy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ProxyPolicy configures the host-mediated runtime guardrail rules.
type ProxyPolicy struct {
	AllowedDomains     []string `json:"allowed_domains" yaml:"allowed_domains"`
	ForbiddenCommands  []string `json:"forbidden_commands" yaml:"forbidden_commands"`
	RedactPII          bool     `json:"redact_pii" yaml:"redact_pii"`
	StrictTypeChecking bool     `json:"strict_type_checking" yaml:"strict_type_checking"`
}

// ToolCallRequest represents an incoming agent tool invocation.
type ToolCallRequest struct {
	ToolName  string                 `json:"tool_name" yaml:"tool_name"`
	Arguments map[string]interface{} `json:"arguments" yaml:"arguments"`
	SessionID string                 `json:"session_id,omitempty" yaml:"session_id,omitempty"`
}

// GuardrailDecision describes whether the tool call is permitted or blocked.
type GuardrailDecision string

const (
	DecisionAllow  GuardrailDecision = "ALLOW"
	DecisionBlock  GuardrailDecision = "BLOCK"
	DecisionRedact GuardrailDecision = "REDACT_AND_ALLOW"
)

// ProxyResponse represents the result of host-mediated guardrail evaluation.
type ProxyResponse struct {
	Decision           GuardrailDecision      `json:"decision" yaml:"decision"`
	SanitizedArguments map[string]interface{} `json:"sanitized_arguments,omitempty" yaml:"sanitized_arguments,omitempty"`
	Reason             string                 `json:"reason,omitempty" yaml:"reason,omitempty"`
	Timestamp          time.Time              `json:"timestamp" yaml:"timestamp"`
}

// DefaultProxyPolicy returns a strict default runtime policy.
func DefaultProxyPolicy() ProxyPolicy {
	return ProxyPolicy{
		AllowedDomains:     []string{"api.github.com", "raw.githubusercontent.com", "pypi.org"},
		ForbiddenCommands:  []string{"rm -rf", "sudo", "curl -s | sh", "wget -O- | sh"},
		RedactPII:          true,
		StrictTypeChecking: true,
	}
}

var piiRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api_key|secret|token|password)\s*=\s*['"]?[a-zA-Z0-9_\-]{8,}['"]?`),
	regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), // Emails
}

// EvaluateToolCall processes a tool call against the proxy policy.
func EvaluateToolCall(ctx context.Context, req ToolCallRequest, policy ProxyPolicy) ProxyResponse {
	if len(policy.AllowedDomains) == 0 {
		policy = DefaultProxyPolicy()
	}

	sanitizedArgs := make(map[string]interface{})
	for k, v := range req.Arguments {
		sanitizedArgs[k] = v
	}

	toolLower := strings.ToLower(req.ToolName)

	// 1. Command execution checks
	if strings.Contains(toolLower, "command") || strings.Contains(toolLower, "bash") || strings.Contains(toolLower, "exec") {
		if cmdVal, ok := req.Arguments["command"].(string); ok {
			for _, forbidden := range policy.ForbiddenCommands {
				if strings.Contains(strings.ToLower(cmdVal), strings.ToLower(forbidden)) {
					return ProxyResponse{
						Decision:  DecisionBlock,
						Reason:    fmt.Sprintf("Forbidden subcommand execution detected: %s", forbidden),
						Timestamp: time.Now().UTC(),
					}
				}
			}
		}
	}

	// 2. Network egress checks
	if strings.Contains(toolLower, "http") || strings.Contains(toolLower, "fetch") || strings.Contains(toolLower, "url") {
		if urlVal, ok := req.Arguments["url"].(string); ok {
			allowed := false
			for _, domain := range policy.AllowedDomains {
				if strings.Contains(strings.ToLower(urlVal), strings.ToLower(domain)) {
					allowed = true
					break
				}
			}
			if !allowed {
				return ProxyResponse{
					Decision:  DecisionBlock,
					Reason:    fmt.Sprintf("Network egress to domain in URL '%s' is not in allowed list", urlVal),
					Timestamp: time.Now().UTC(),
				}
			}
		}
	}

	// 3. PII & Secret Redaction
	wasRedacted := false
	if policy.RedactPII {
		for k, v := range sanitizedArgs {
			if strVal, ok := v.(string); ok {
				newVal := strVal
				for _, re := range piiRegexes {
					if re.MatchString(newVal) {
						newVal = re.ReplaceAllString(newVal, "[REDACTED]")
						wasRedacted = true
					}
				}
				sanitizedArgs[k] = newVal
			}
		}
	}

	decision := DecisionAllow
	if wasRedacted {
		decision = DecisionRedact
	}

	return ProxyResponse{
		Decision:           decision,
		SanitizedArguments: sanitizedArgs,
		Timestamp:          time.Now().UTC(),
	}
}
