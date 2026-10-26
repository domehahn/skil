package runtimeproxy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/domehahn/skil/internal/receipt"
)

// ProxyPolicy configures the host-mediated runtime guardrail rules and optional
// mandatory proof-carrying authorization enforcement.
type ProxyPolicy struct {
	AllowedDomains       []string `json:"allowed_domains" yaml:"allowed_domains"`
	ForbiddenCommands    []string `json:"forbidden_commands" yaml:"forbidden_commands"`
	RedactPII            bool     `json:"redact_pii" yaml:"redact_pii"`
	StrictTypeChecking   bool     `json:"strict_type_checking" yaml:"strict_type_checking"`
	RequireAuthorization bool     `json:"require_authorization,omitempty" yaml:"require_authorization,omitempty"`
}

// ToolCallRequest represents an incoming agent tool invocation.
type ToolCallRequest struct {
	ToolName               string                          `json:"tool_name" yaml:"tool_name"`
	Arguments              map[string]interface{}          `json:"arguments" yaml:"arguments"`
	SessionID              string                          `json:"session_id,omitempty" yaml:"session_id,omitempty"`
	SubjectID              string                          `json:"subject_id,omitempty" yaml:"subject_id,omitempty"`
	SubjectDigest          string                          `json:"subject_digest,omitempty" yaml:"subject_digest,omitempty"`
	AgentID                string                          `json:"agent_id,omitempty" yaml:"agent_id,omitempty"`
	ParentAgentID          string                          `json:"parent_agent_id,omitempty" yaml:"parent_agent_id,omitempty"`
	Capability             string                          `json:"capability,omitempty" yaml:"capability,omitempty"`
	Target                 string                          `json:"target,omitempty" yaml:"target,omitempty"`
	NegotiatedToolSchema   any                             `json:"-" yaml:"-"`
	NegotiatedSchemaDigest string                          `json:"negotiated_schema_digest,omitempty" yaml:"negotiated_schema_digest,omitempty"`
	Authorization          *receipt.ExecutionAuthorization `json:"authorization,omitempty" yaml:"authorization,omitempty"`
}

// GuardrailDecision describes whether the tool call is permitted or blocked.
type GuardrailDecision string

const (
	DecisionAllow  GuardrailDecision = "ALLOW"
	DecisionBlock  GuardrailDecision = "BLOCK"
	DecisionRedact GuardrailDecision = "REDACT_AND_ALLOW"
)

// ProxyResponse represents the result of host-mediated guardrail and proof-carrying authorization evaluation.
type ProxyResponse struct {
	Decision                GuardrailDecision                    `json:"decision" yaml:"decision"`
	SanitizedArguments      map[string]interface{}               `json:"sanitized_arguments,omitempty" yaml:"sanitized_arguments,omitempty"`
	Reason                  string                               `json:"reason,omitempty" yaml:"reason,omitempty"`
	Timestamp               time.Time                            `json:"timestamp" yaml:"timestamp"`
	Authorized              bool                                 `json:"authorized,omitempty" yaml:"authorized,omitempty"`
	ArgumentsMutated        bool                                 `json:"arguments_mutated,omitempty" yaml:"arguments_mutated,omitempty"`
	OriginalArgumentDigest  string                               `json:"original_argument_digest,omitempty" yaml:"original_argument_digest,omitempty"`
	EffectiveArgumentDigest string                               `json:"effective_argument_digest,omitempty" yaml:"effective_argument_digest,omitempty"`
	Receipt                 *receipt.OperationEnforcementReceipt `json:"receipt,omitempty" yaml:"receipt,omitempty"`
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

// EvaluateToolCall processes a tool call against the proxy guardrail policy.
func EvaluateToolCall(ctx context.Context, req ToolCallRequest, policy ProxyPolicy) ProxyResponse {
	_ = ctx
	if len(policy.AllowedDomains) == 0 && len(policy.ForbiddenCommands) == 0 {
		def := DefaultProxyPolicy()
		def.RequireAuthorization = policy.RequireAuthorization
		policy = def
	}

	sanitizedArgs := make(map[string]interface{}, len(req.Arguments))
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
			if u, err := url.Parse(urlVal); err == nil && u.Host != "" {
				host := strings.ToLower(u.Host)
				if idx := strings.Index(host, ":"); idx != -1 {
					host = host[:idx]
				}
				allowed := false
				for _, domain := range policy.AllowedDomains {
					d := strings.ToLower(domain)
					if host == d || strings.HasSuffix(host, "."+d) {
						allowed = true
						break
					}
				}
				if !allowed {
					return ProxyResponse{
						Decision:  DecisionBlock,
						Reason:    fmt.Sprintf("Network egress host '%s' is not in allowed domain list", host),
						Timestamp: time.Now().UTC(),
					}
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

	origDigest, _ := receipt.CanonicalArgumentDigest(req.Arguments)
	effDigest, _ := receipt.CanonicalArgumentDigest(sanitizedArgs)

	return ProxyResponse{
		Decision:                decision,
		SanitizedArguments:      sanitizedArgs,
		Timestamp:               time.Now().UTC(),
		ArgumentsMutated:        origDigest != effDigest,
		OriginalArgumentDigest:  origDigest,
		EffectiveArgumentDigest: effDigest,
	}
}

// ReauthorizeFunc issues a fresh ExecutionAuthorization bound to the post-sanitization
// effective arguments when guardrail redaction modifies a tool call's arguments.
type ReauthorizeFunc func(
	ctx context.Context,
	req ToolCallRequest,
	sanitizedArgs map[string]any,
	originalAuth receipt.ExecutionAuthorization,
) (*receipt.ExecutionAuthorization, error)

// RuntimeProxyConfig configures combined guardrail + proof-carrying authorization enforcement.
type RuntimeProxyConfig struct {
	Policy               ProxyPolicy
	Gateway              *receipt.ExecutionGateway
	RequireAuthorization bool
	Reauthorizer         ReauthorizeFunc
	RuntimePrivateKey    ed25519.PrivateKey
	RuntimeKeyID         string
	DefaultSubjectID     string
	DefaultSubjectDigest string
	DefaultAgentID       string
	DefaultSessionID     string
	ActivePolicyID       string
	ActivePolicyDigest   string
}

// RuntimeProxy combines host-mediated guardrail evaluation with mandatory
// proof-carrying operation authorization.
type RuntimeProxy struct {
	cfg RuntimeProxyConfig
	seq atomic.Uint64
}

func NewRuntimeProxy(cfg RuntimeProxyConfig) *RuntimeProxy {
	return &RuntimeProxy{cfg: cfg}
}

// EnforceAndExecute runs guardrail checks first and then validates the proof-carrying
// ExecutionAuthorization against the effective (post-sanitization) operation before
// invoking execFn. Unauthorized or blocked calls never reach execFn.
func (p *RuntimeProxy) EnforceAndExecute(
	ctx context.Context,
	req ToolCallRequest,
	execFn func(ctx context.Context, effectiveArgs map[string]any) (receipt.OperationExecutionResult, error),
) (ProxyResponse, error) {
	resp := EvaluateToolCall(ctx, req, p.cfg.Policy)
	if resp.Decision == DecisionBlock {
		return resp, fmt.Errorf("blocked by runtime proxy guardrail: %s", resp.Reason)
	}

	mustAuth := p.cfg.RequireAuthorization || p.cfg.Policy.RequireAuthorization || req.Authorization != nil
	if !mustAuth {
		if execFn != nil {
			if _, err := execFn(ctx, resp.SanitizedArguments); err != nil {
				return resp, err
			}
		}
		return resp, nil
	}

	if p.cfg.Gateway == nil {
		resp.Decision = DecisionBlock
		resp.Authorized = false
		resp.Reason = "mandatory proof-carrying authorization is enabled but ExecutionGateway is nil"
		return resp, errors.New(resp.Reason)
	}
	if req.Authorization == nil {
		resp.Decision = DecisionBlock
		resp.Authorized = false
		resp.Reason = "missing required proof-carrying ExecutionAuthorization"
		return resp, errors.New(resp.Reason)
	}

	effectiveAuth := *req.Authorization

	// P0.3: Ensure argument sanitization does not invalidate authorization binding unnoticed.
	// If arguments changed during sanitization and the authorization is not already bound to
	// the effective argument digest, either reauthorize the effective operation or reject execution.
	if resp.ArgumentsMutated && effectiveAuth.ArgumentDigest != resp.EffectiveArgumentDigest {
		if p.cfg.Reauthorizer == nil {
			resp.Decision = DecisionBlock
			resp.Authorized = false
			resp.Reason = fmt.Sprintf(
				"argument sanitization modified canonical argument digest (%s -> %s) and no reauthorizer is configured",
				resp.OriginalArgumentDigest, resp.EffectiveArgumentDigest,
			)
			return resp, errors.New(resp.Reason)
		}
		reauth, err := p.cfg.Reauthorizer(ctx, req, resp.SanitizedArguments, effectiveAuth)
		if err != nil || reauth == nil {
			resp.Decision = DecisionBlock
			resp.Authorized = false
			resp.Reason = fmt.Sprintf("reauthorization of sanitized arguments failed: %v", err)
			return resp, errors.New(resp.Reason)
		}
		effectiveAuth = *reauth
	}

	capName := strings.TrimSpace(req.Capability)
	if capName == "" {
		capName = inferCapability(req.ToolName, effectiveAuth.RequestedCapability)
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = inferTarget(req.ToolName, resp.SanitizedArguments)
	}
	cmdText, _ := resp.SanitizedArguments["command"].(string)

	protReq := receipt.ProtectedOperationRequest{
		ExecutionID:            fmt.Sprintf("proxy-exec-%d", p.seq.Add(1)),
		SubjectID:              firstStr(req.SubjectID, p.cfg.DefaultSubjectID, effectiveAuth.SubjectID),
		SubjectDigest:          firstStr(req.SubjectDigest, p.cfg.DefaultSubjectDigest, effectiveAuth.SubjectDigest),
		AgentID:                firstStr(req.AgentID, p.cfg.DefaultAgentID, effectiveAuth.AgentID),
		SessionID:              firstStr(req.SessionID, p.cfg.DefaultSessionID, effectiveAuth.SessionID),
		ParentAgentID:          req.ParentAgentID,
		ToolOrServerID:         req.ToolName,
		Capability:             capName,
		Target:                 target,
		CommandText:            cmdText,
		Arguments:              resp.SanitizedArguments,
		NegotiatedToolSchema:   req.NegotiatedToolSchema,
		NegotiatedSchemaDigest: req.NegotiatedSchemaDigest,
		ActivePolicyID:         p.cfg.ActivePolicyID,
		ActivePolicyDigest:     p.cfg.ActivePolicyDigest,
	}

	opReceipt, err := p.cfg.Gateway.AuthorizeAndExecute(
		ctx,
		effectiveAuth,
		protReq,
		p.cfg.RuntimePrivateKey,
		p.cfg.RuntimeKeyID,
		func(callCtx context.Context, _ receipt.ProtectedOperationRequest) (receipt.OperationExecutionResult, error) {
			if execFn == nil {
				return receipt.OperationExecutionResult{
					Accepted:        true,
					Enforced:        true,
					TransportStatus: 200,
				}, nil
			}
			return execFn(callCtx, resp.SanitizedArguments)
		},
	)
	resp.Receipt = &opReceipt
	if err != nil {
		resp.Decision = DecisionBlock
		resp.Authorized = false
		resp.Reason = err.Error()
		return resp, err
	}

	resp.Authorized = true
	return resp, nil
}

func inferCapability(toolName, fallback string) string {
	if strings.TrimSpace(fallback) != "" {
		return strings.TrimSpace(fallback)
	}
	lower := strings.ToLower(toolName)
	switch {
	case strings.Contains(lower, "command") || strings.Contains(lower, "bash") || strings.Contains(lower, "exec"):
		return "commands.execute"
	case strings.Contains(lower, "http") || strings.Contains(lower, "fetch") || strings.Contains(lower, "url"):
		return "network.outbound"
	default:
		return "tools.call"
	}
}

func inferTarget(toolName string, args map[string]any) string {
	if cmd, ok := args["command"].(string); ok && cmd != "" {
		return cmd
	}
	if u, ok := args["url"].(string); ok && u != "" {
		return u
	}
	if path, ok := args["path"].(string); ok && path != "" {
		return path
	}
	return toolName
}

func firstStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
