package mcpinterceptor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"github.com/domehahn/skil/internal/mcpassure"
	"github.com/domehahn/skil/internal/receipt"
)

const (
	JSONRPCParseError     = -32700
	JSONRPCInvalidRequest = -32600
	JSONRPCMethodNotFound = -32601
	JSONRPCInvalidParams  = -32602
	JSONRPCInternalError  = -32603
	JSONRPCUnauthorized   = -32001
)

type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   any             `json:"error,omitempty"`
}

// ToolCallMeta carries optional MCP _meta security context fields.
type ToolCallMeta struct {
	AgentID       string                          `json:"agent_id,omitempty"`
	ParentAgentID string                          `json:"parent_agent_id,omitempty"`
	SessionID     string                          `json:"session_id,omitempty"`
	Authorization *receipt.ExecutionAuthorization `json:"skil_authorization,omitempty"`
}

// ToolCallParams represents the structured parameters of a JSON-RPC tools/call request.
type ToolCallParams struct {
	Name          string                          `json:"name"`
	Arguments     map[string]any                  `json:"arguments,omitempty"`
	Authorization *receipt.ExecutionAuthorization `json:"_skil_authorization,omitempty"`
	Meta          *ToolCallMeta                   `json:"_meta,omitempty"`
}

// InterceptorOptions configures MCP message filtering, Surface Lock validation,
// and mandatory proof-carrying execution authorization.
type InterceptorOptions struct {
	SurfaceLockPath    string
	SurfaceLock        *mcpassure.SurfaceLock
	Strict             bool
	RequireSurfaceLock bool
	MandatoryAuth      bool
	Gateway            *receipt.ExecutionGateway
	ServerID           string
	SubjectID          string
	SubjectDigest      string
	DefaultAgentID     string
	DefaultParentAgent string
	DefaultSessionID   string
	ActivePolicyID     string
	ActivePolicyDigest string
	LiveToolSchemas    map[string]any
	RuntimePrivateKey  ed25519.PrivateKey
	RuntimeKeyID       string
	// OnForward is invoked only when a client message passes all security checks.
	// Blocked or malformed messages never reach OnForward.
	OnForward func(ctx context.Context, raw []byte) error
	// ErrorOut, when non-nil during RunStream, receives JSON-RPC error responses
	// for blocked requests so blocked messages are never written to out.
	ErrorOut io.Writer
}

type Interceptor struct {
	options     InterceptorOptions
	surfaceLock *mcpassure.SurfaceLock
	seq         atomic.Uint64
}

func NewInterceptor(opts InterceptorOptions) (*Interceptor, error) {
	lock := opts.SurfaceLock
	mustHaveLock := opts.RequireSurfaceLock || opts.MandatoryAuth || (opts.Strict && strings.TrimSpace(opts.SurfaceLockPath) != "")

	if strings.TrimSpace(opts.SurfaceLockPath) != "" {
		data, err := os.ReadFile(opts.SurfaceLockPath)
		if err != nil {
			if mustHaveLock {
				return nil, fmt.Errorf("failed to read required MCP surface lock %q: %w", opts.SurfaceLockPath, err)
			}
		} else {
			var loaded mcpassure.SurfaceLock
			if err := json.Unmarshal(data, &loaded); err != nil {
				if mustHaveLock {
					return nil, fmt.Errorf("failed to parse MCP surface lock %q: %w", opts.SurfaceLockPath, err)
				}
			} else {
				lock = &loaded
			}
		}
	}

	if mustHaveLock {
		if lock == nil || len(lock.Tools) == 0 {
			return nil, errors.New("MCP surface lock with non-empty tools map is required when strict/mandatory enforcement is enabled")
		}
	}

	if opts.MandatoryAuth && opts.Gateway == nil {
		return nil, errors.New("ExecutionGateway is required when MandatoryAuth is enabled on MCP interceptor")
	}

	return &Interceptor{
		options:     opts,
		surfaceLock: lock,
	}, nil
}

func (i *Interceptor) enforceMode() bool {
	return i.options.Strict || i.options.RequireSurfaceLock || i.options.MandatoryAuth || i.options.Gateway != nil
}

func marshalJSONRPCError(id any, code int, message string) ([]byte, error) {
	errResp := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: map[string]any{
			"code":    code,
			"message": message,
		},
	}
	return json.Marshal(errResp)
}

// InspectMessage evaluates a raw JSON-RPC message and returns the outbound bytes,
// whether the message was blocked by security enforcement, and any fatal error.
func (i *Interceptor) InspectMessage(ctx context.Context, data []byte, fromClient bool) (out []byte, blocked bool, err error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		if i.enforceMode() {
			resp, mErr := marshalJSONRPCError(nil, JSONRPCParseError, "[skil] BLOCKED: empty or malformed JSON-RPC message")
			return resp, true, mErr
		}
		return data, false, nil
	}

	var msg JSONRPCMessage
	if uErr := json.Unmarshal(trimmed, &msg); uErr != nil {
		if i.enforceMode() {
			resp, mErr := marshalJSONRPCError(nil, JSONRPCParseError, fmt.Sprintf("[skil] BLOCKED: malformed JSON-RPC payload: %v", uErr))
			return resp, true, mErr
		}
		return data, false, nil
	}

	if i.enforceMode() {
		if msg.JSONRPC != "2.0" {
			resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCInvalidRequest, "[skil] BLOCKED: invalid JSON-RPC version (expected \"2.0\")")
			return resp, true, mErr
		}
		if fromClient && strings.TrimSpace(msg.Method) == "" && len(msg.Result) == 0 && msg.Error == nil {
			resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCInvalidRequest, "[skil] BLOCKED: client JSON-RPC request missing method")
			return resp, true, mErr
		}
	}

	// Non-tools/call messages (e.g. initialize, ping, notifications, tools/list, server responses) are allowed through.
	if !fromClient || msg.Method != "tools/call" {
		if fromClient && i.options.OnForward != nil {
			if fErr := i.options.OnForward(ctx, data); fErr != nil {
				return nil, true, fErr
			}
		}
		return data, false, nil
	}

	// Strictly validate tools/call parameters
	if len(bytes.TrimSpace(msg.Params)) == 0 || bytes.Equal(bytes.TrimSpace(msg.Params), []byte("null")) {
		resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCInvalidParams, "[skil] BLOCKED: malformed tools/call parameters: params object is required")
		return resp, true, mErr
	}

	var rawParams map[string]json.RawMessage
	if uErr := json.Unmarshal(msg.Params, &rawParams); uErr != nil {
		resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCInvalidParams, fmt.Sprintf("[skil] BLOCKED: malformed tools/call parameters: %v", uErr))
		return resp, true, mErr
	}

	if rawArgs, hasArgs := rawParams["arguments"]; hasArgs {
		trimmedArgs := bytes.TrimSpace(rawArgs)
		if len(trimmedArgs) > 0 && !bytes.Equal(trimmedArgs, []byte("null")) {
			var checkMap map[string]any
			if uErr := json.Unmarshal(trimmedArgs, &checkMap); uErr != nil {
				resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCInvalidParams, "[skil] BLOCKED: malformed tools/call arguments: must be a JSON object")
				return resp, true, mErr
			}
		}
	}

	var params ToolCallParams
	if uErr := json.Unmarshal(msg.Params, &params); uErr != nil {
		resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCInvalidParams, fmt.Sprintf("[skil] BLOCKED: invalid tools/call parameter structure: %v", uErr))
		return resp, true, mErr
	}
	params.Name = strings.TrimSpace(params.Name)
	if params.Name == "" {
		resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCInvalidParams, "[skil] BLOCKED: tools/call requires a non-empty tool name")
		return resp, true, mErr
	}
	if params.Arguments == nil {
		params.Arguments = map[string]any{}
	}

	// 1. Surface Lock verification (missing or empty surface lock can NEVER silently disable enforcement)
	var lockedDigest string
	if i.enforceMode() {
		if i.surfaceLock == nil || len(i.surfaceLock.Tools) == 0 {
			resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCInternalError, "[skil] BLOCKED: required MCP surface lock is missing or empty")
			return resp, true, mErr
		}
		var allowed bool
		lockedDigest, allowed = i.surfaceLock.Tools[params.Name]
		if !allowed || strings.TrimSpace(lockedDigest) == "" {
			resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCMethodNotFound, fmt.Sprintf("[skil] BLOCKED: Dynamic MCP Tool %q is not authorized in surface lock", params.Name))
			return resp, true, mErr
		}
	}

	// If LiveToolSchemas is provided, verify live schema matches the surface lock before gateway check.
	var liveSchema any
	if i.options.LiveToolSchemas != nil {
		liveSchema = i.options.LiveToolSchemas[params.Name]
		if liveSchema != nil && lockedDigest != "" {
			computedDigest, sErr := receipt.CanonicalSchemaDigest(liveSchema)
			if sErr != nil {
				resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCUnauthorized, fmt.Sprintf("[skil] BLOCKED: invalid live MCP tool schema for %q: %v", params.Name, sErr))
				return resp, true, mErr
			}
			normLocked := lockedDigest
			if !strings.HasPrefix(normLocked, "sha256:") {
				normLocked = "sha256:" + normLocked
			}
			if computedDigest != normLocked {
				resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCUnauthorized, fmt.Sprintf("[skil] BLOCKED: MCP tool %q schema drifted from surface lock (%s != %s)", params.Name, computedDigest, normLocked))
				return resp, true, mErr
			}
		}
	}

	// 2. Mandatory Proof-Carrying Authorization via ExecutionGateway
	auth := params.Authorization
	if auth == nil && params.Meta != nil {
		auth = params.Meta.Authorization
	}

	if i.options.MandatoryAuth || i.options.Gateway != nil {
		if i.options.Gateway == nil {
			resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCInternalError, "[skil] BLOCKED: ExecutionGateway is not configured for mandatory authorization")
			return resp, true, mErr
		}
		if auth == nil {
			resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCUnauthorized, fmt.Sprintf("[skil] BLOCKED: missing proof-carrying ExecutionAuthorization for tool %q", params.Name))
			return resp, true, mErr
		}

		agentID := i.options.DefaultAgentID
		parentAgentID := i.options.DefaultParentAgent
		sessionID := i.options.DefaultSessionID
		if params.Meta != nil {
			if params.Meta.AgentID != "" {
				agentID = params.Meta.AgentID
			}
			if params.Meta.ParentAgentID != "" {
				parentAgentID = params.Meta.ParentAgentID
			}
			if params.Meta.SessionID != "" {
				sessionID = params.Meta.SessionID
			}
		}
		if agentID == "" {
			agentID = auth.AgentID
		}
		if sessionID == "" {
			sessionID = auth.SessionID
		}

		serverID := strings.TrimSpace(i.options.ServerID)
		if serverID == "" {
			serverID = auth.ToolOrServerID
		}
		subjectID := firstNonEmptyStr(i.options.SubjectID, auth.SubjectID)
		subjectDigest := firstNonEmptyStr(i.options.SubjectDigest, auth.SubjectDigest)

		protReq := receipt.ProtectedOperationRequest{
			ExecutionID:            fmt.Sprintf("mcp-call-%d", i.seq.Add(1)),
			SubjectID:              subjectID,
			SubjectDigest:          subjectDigest,
			AgentID:                agentID,
			SessionID:              sessionID,
			ParentAgentID:          parentAgentID,
			ToolOrServerID:         serverID,
			Capability:             "mcp.invoke",
			Target:                 params.Name,
			Arguments:              params.Arguments,
			NegotiatedToolSchema:   liveSchema,
			NegotiatedSchemaDigest: lockedDigest,
			ActivePolicyID:         i.options.ActivePolicyID,
			ActivePolicyDigest:     i.options.ActivePolicyDigest,
		}

		if vErr := i.options.Gateway.ValidateAuthorization(*auth, protReq); vErr != nil {
			resp, mErr := marshalJSONRPCError(msg.ID, JSONRPCUnauthorized, fmt.Sprintf("[skil] BLOCKED: MCP authorization rejected for %q: %v", params.Name, vErr))
			return resp, true, mErr
		}
	}

	if i.options.OnForward != nil {
		if fErr := i.options.OnForward(ctx, data); fErr != nil {
			return nil, true, fErr
		}
	}

	return data, false, nil
}

// FilterMessage evaluates a JSON-RPC line and returns either the allowed message
// or a JSON-RPC error object when blocked.
func (i *Interceptor) FilterMessage(data []byte, fromClient bool) ([]byte, error) {
	out, _, err := i.InspectMessage(context.Background(), data, fromClient)
	return out, err
}

// RunStream processes newline-delimited JSON-RPC messages from in.
// When i.options.ErrorOut is configured, blocked client messages write their
// JSON-RPC error response to ErrorOut and are never written to out (the server stream).
func (i *Interceptor) RunStream(in io.Reader, out io.Writer, fromClient bool) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		filtered, blocked, err := i.InspectMessage(context.Background(), line, fromClient)
		if err != nil {
			return err
		}
		if blocked && i.options.ErrorOut != nil {
			if _, wErr := i.options.ErrorOut.Write(append(filtered, '\n')); wErr != nil {
				return wErr
			}
			continue
		}
		if _, err := out.Write(append(filtered, '\n')); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
