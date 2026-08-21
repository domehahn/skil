// Package mcpassure implements Dynamic MCP Assurance: it launches an
// operator-supplied MCP server command inside skil's existing sandboxed
// isolation (internal/eval.StreamingIsolationProvider), performs the real
// MCP JSON-RPC-over-stdio handshake (initialize, notifications/initialized,
// tools/list, prompts/list, resources/list), and compares what the server
// actually declares at runtime against .skil/mcp-tools.lock.json — the same
// lock SKIL-MCP-005 checks static manifest metadata against.
//
// This is a stronger signal than static analysis of an MCP manifest file:
// SKIL-MCP-005 can only catch a mismatch between a manifest and its lock; a
// server can present one description in its manifest/README and a
// different one over the wire (a runtime rug pull static parsing can never
// see). Executing the server, even sandboxed, is the qualitatively
// different, higher-risk step every other feature added this session
// deliberately avoided — hence it is never automatic: the operator must
// explicitly supply the command to run (skil never executes a manifest-
// declared command on its own), exactly mirroring skil assure's own
// --runtime-command requirement for behavioral evaluation.
package mcpassure

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/domehahn/skil/internal/eval"
)

// Options bounds the handshake: skil's fail-closed philosophy means a
// misbehaving or hung MCP server must not be able to stall or exhaust the
// caller — every round trip has a timeout and every response is
// size-bounded.
type Options struct {
	// Timeout bounds each individual request/response round trip.
	// Zero uses DefaultTimeout.
	Timeout time.Duration
	// MaxResponseBytes bounds each single JSON-RPC response line/frame.
	// Zero uses DefaultMaxResponseBytes.
	MaxResponseBytes int64
}

const (
	DefaultTimeout          = 10 * time.Second
	DefaultMaxResponseBytes = 1 << 20 // 1 MiB, matching skil assure's --max-output-bytes default
	protocolVersion         = "2025-06-18"
)

// Tool is an MCP tool as declared by the server itself over the wire, not
// as parsed from a manifest file.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// Prompt and Resource are captured for completeness/reporting; only Tools
// are compared against the metadata lock, since that lock's schema
// (mcp-tools-lock-v1.schema.json) is tool-scoped.
type Prompt struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// Discovery is everything observed during one live handshake.
type Discovery struct {
	ProtocolVersion string
	ServerName      string
	ServerVersion   string
	Tools           []Tool
	Prompts         []Prompt
	Resources       []Resource
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcErrorPayload struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *int             `json:"id"`
	Result  json.RawMessage  `json:"result"`
	Error   *rpcErrorPayload `json:"error"`
}

// methodNotFound is the standard JSON-RPC reserved error code; a server
// that doesn't implement prompts/list or resources/list is expected to
// return this rather than a transport failure, so it is treated as "this
// capability is simply absent" rather than a fatal handshake error.
const methodNotFound = -32601

// Discover drives the full MCP initialization handshake and capability
// listing over an already-started sandboxed session, returning everything
// the server declared about itself. It never writes to the host or the
// network itself; all it does is speak JSON-RPC over the Session's stdio,
// which internal/eval.Session guarantees is sandboxed identically to
// IsolationProvider.Run.
func Discover(ctx context.Context, session eval.Session, opts Options) (Discovery, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxBytes := opts.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponseBytes
	}
	client := &client{
		ctx: ctx, session: session, timeout: timeout,
		scanner: bufio.NewScanner(session.Stdout()),
	}
	client.scanner.Buffer(make([]byte, 0, 64*1024), int(maxBytes))

	initResult, err := client.call("initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "skil", "version": "dynamic-assurance"},
	})
	if err != nil {
		return Discovery{}, fmt.Errorf("mcp initialize: %w", err)
	}
	var initialized struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(initResult, &initialized); err != nil {
		return Discovery{}, fmt.Errorf("mcp initialize: parse result: %w", err)
	}
	if err := client.notify("notifications/initialized", nil); err != nil {
		return Discovery{}, fmt.Errorf("mcp notifications/initialized: %w", err)
	}

	discovery := Discovery{
		ProtocolVersion: initialized.ProtocolVersion,
		ServerName:      initialized.ServerInfo.Name,
		ServerVersion:   initialized.ServerInfo.Version,
	}

	toolsResult, err := client.call("tools/list", map[string]any{})
	if err != nil {
		return Discovery{}, fmt.Errorf("mcp tools/list: %w", err)
	}
	var tools struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(toolsResult, &tools); err != nil {
		return Discovery{}, fmt.Errorf("mcp tools/list: parse result: %w", err)
	}
	discovery.Tools = tools.Tools

	if promptsResult, err := client.call("prompts/list", map[string]any{}); err == nil {
		var prompts struct {
			Prompts []Prompt `json:"prompts"`
		}
		if err := json.Unmarshal(promptsResult, &prompts); err == nil {
			discovery.Prompts = prompts.Prompts
		}
	} else if !errors.Is(err, errMethodNotFound) {
		return Discovery{}, fmt.Errorf("mcp prompts/list: %w", err)
	}

	if resourcesResult, err := client.call("resources/list", map[string]any{}); err == nil {
		var resources struct {
			Resources []Resource `json:"resources"`
		}
		if err := json.Unmarshal(resourcesResult, &resources); err == nil {
			discovery.Resources = resources.Resources
		}
	} else if !errors.Is(err, errMethodNotFound) {
		return Discovery{}, fmt.Errorf("mcp resources/list: %w", err)
	}

	return discovery, nil
}

var errMethodNotFound = errors.New("mcp: method not found")

type client struct {
	ctx     context.Context
	session eval.Session
	timeout time.Duration
	scanner *bufio.Scanner
	nextID  int
}

func (c *client) call(method string, params any) (json.RawMessage, error) {
	c.nextID++
	id := c.nextID
	if err := c.write(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}); err != nil {
		return nil, err
	}
	for {
		line, err := c.readLine()
		if err != nil {
			return nil, err
		}
		var response rpcResponse
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			// Not a well-formed JSON-RPC frame (e.g. server log noise on
			// stdout); skip it rather than failing the whole handshake.
			continue
		}
		if response.ID == nil || *response.ID != id {
			// A notification or a reply to an earlier call; keep reading
			// for the response we actually asked for.
			continue
		}
		if response.Error != nil {
			if response.Error.Code == methodNotFound {
				return nil, errMethodNotFound
			}
			return nil, fmt.Errorf("mcp error %d: %s", response.Error.Code, response.Error.Message)
		}
		return response.Result, nil
	}
}

// notify sends a JSON-RPC notification (no id, no response expected).
func (c *client) notify(method string, params any) error {
	return c.write(rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
}

func (c *client) write(request rpcRequest) error {
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = c.session.Stdin().Write(data)
	return err
}

type lineResult struct {
	line string
	ok   bool
	err  error
}

// readLine reads one newline-delimited JSON-RPC frame, bounded by
// c.timeout: a hung or non-responsive sandboxed server must not be able to
// block the caller forever. On timeout or context cancellation the session
// is forcibly closed, which unblocks the in-flight pipe read.
func (c *client) readLine() (string, error) {
	resultCh := make(chan lineResult, 1)
	go func() {
		ok := c.scanner.Scan()
		resultCh <- lineResult{line: c.scanner.Text(), ok: ok, err: c.scanner.Err()}
	}()
	timer := time.NewTimer(c.timeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		if !result.ok {
			if result.err != nil {
				return "", fmt.Errorf("read mcp response: %w", result.err)
			}
			return "", io.ErrUnexpectedEOF
		}
		return result.line, nil
	case <-c.ctx.Done():
		_ = c.session.Close()
		return "", c.ctx.Err()
	case <-timer.C:
		_ = c.session.Close()
		return "", fmt.Errorf("mcp handshake: no response within %s", c.timeout)
	}
}
