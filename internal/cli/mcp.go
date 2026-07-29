package cli

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxMCPMessageBytes = 4 << 20

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (a *App) serve(ctx context.Context, args []string) int {
	fs := newFlags("serve", a.Err)
	stdio := fs.Bool("stdio", false, "serve MCP over newline-delimited stdio")
	listen := fs.String("listen", "", "serve authenticated MCP HTTP on a loopback address")
	tokenEnv := fs.String("token-env", "SKIL_MCP_TOKEN", "environment variable containing the HTTP bearer token")
	root := fs.String("root", "", "only permit scans below this directory")
	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}
	if (*stdio == (*listen != "")) || *root == "" {
		return a.inputError(errors.New("serve requires --root and exactly one of --stdio or --listen"))
	}
	info, err := os.Lstat(*root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return a.inputError(errors.New("MCP root must be a non-symlink directory"))
	}
	absoluteRoot, err := filepath.Abs(*root)
	if err != nil {
		return a.inputError(err)
	}
	if *stdio {
		if err := a.serveMCPStdio(ctx, absoluteRoot); err != nil {
			return a.inputError(err)
		}
		return ExitOK
	}
	token := os.Getenv(*tokenEnv)
	if len(token) < 32 {
		return a.inputError(fmt.Errorf("%s must contain at least 32 characters", *tokenEnv))
	}
	if err := a.serveMCPHTTP(ctx, absoluteRoot, *listen, token); err != nil {
		return a.inputError(err)
	}
	return ExitOK
}

func (a *App) serveMCPHTTP(ctx context.Context, root, address, token string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("--listen must be a host:port address")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("MCP HTTP currently permits only explicit loopback addresses")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for MCP HTTP: %w", err)
	}
	server := &http.Server{
		Handler:           a.mcpHTTPHandler(ctx, root, token),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *App) mcpHTTPHandler(ctx context.Context, root, token string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if request.Method != http.MethodPost || request.URL.Path != "/mcp" {
			http.NotFound(writer, request)
			return
		}
		supplied := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		if len(supplied) != len(token) || subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) != 1 {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxMCPMessageBytes)
		var message mcpRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&message); err != nil {
			http.Error(writer, "invalid JSON-RPC request", http.StatusBadRequest)
			return
		}
		response, emit := a.handleMCP(ctx, root, message)
		if !emit {
			writer.WriteHeader(http.StatusAccepted)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(response)
	})
}

func (a *App) serveMCPStdio(ctx context.Context, root string) error {
	scanner := bufio.NewScanner(a.In)
	scanner.Buffer(make([]byte, 64<<10), maxMCPMessageBytes)
	encoder := json.NewEncoder(a.Out)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var request mcpRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			if err := encoder.Encode(mcpResponse{JSONRPC: "2.0", Error: &mcpError{Code: -32700, Message: "invalid JSON"}}); err != nil {
				return err
			}
			continue
		}
		response, emit := a.handleMCP(ctx, root, request)
		if emit {
			if err := encoder.Encode(response); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read MCP message (maximum %d bytes): %w", maxMCPMessageBytes, err)
	}
	return nil
}

func (a *App) handleMCP(ctx context.Context, root string, request mcpRequest) (mcpResponse, bool) {
	response := mcpResponse{JSONRPC: "2.0", ID: request.ID}
	if request.JSONRPC != "2.0" || request.Method == "" {
		response.Error = &mcpError{Code: -32600, Message: "invalid request"}
		return response, true
	}
	switch request.Method {
	case "notifications/initialized":
		return mcpResponse{}, false
	case "initialize":
		response.Result = map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]string{"name": "skil", "version": "1"},
		}
	case "tools/list":
		response.Result = map[string]any{"tools": []any{map[string]any{
			"name": "skil_scan", "description": "Statically inspect one local skill below the configured server root.",
			"inputSchema": map[string]any{
				"type": "object", "additionalProperties": false, "required": []string{"path"},
				"properties": map[string]any{"path": map[string]string{"type": "string"}},
			},
		}}}
	case "tools/call":
		result, err := a.handleMCPToolCall(ctx, root, request.Params)
		if err != nil {
			response.Result = map[string]any{"isError": true, "content": []any{map[string]string{"type": "text", "text": err.Error()}}}
		} else {
			response.Result = result
		}
	default:
		response.Error = &mcpError{Code: -32601, Message: "method not found"}
	}
	return response, true
}

func (a *App) handleMCPToolCall(ctx context.Context, root string, raw json.RawMessage) (any, error) {
	var params struct {
		Name      string `json:"name"`
		Arguments struct {
			Path string `json:"path"`
		} `json:"arguments"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&params); err != nil {
		return nil, errors.New("invalid tool arguments")
	}
	if params.Name != "skil_scan" || params.Arguments.Path == "" {
		return nil, errors.New("unknown tool or missing path")
	}
	target, err := confinedMCPPath(root, params.Arguments.Path)
	if err != nil {
		return nil, err
	}
	scan, _, err := a.performScan(ctx, target, "")
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	payload, err := json.Marshal(scan)
	if err != nil {
		return nil, err
	}
	return map[string]any{"isError": false, "content": []any{map[string]string{"type": "text", "text": string(payload)}}}, nil
}

func confinedMCPPath(root, requested string) (string, error) {
	if filepath.IsAbs(requested) || strings.ContainsRune(requested, '\x00') {
		return "", errors.New("scan path must be relative to the configured root")
	}
	target := filepath.Join(root, filepath.Clean(requested))
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("scan path escapes the configured root")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", errors.New("configured root cannot be resolved")
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", errors.New("scan path cannot be resolved")
	}
	relative, err = filepath.Rel(resolvedRoot, resolvedTarget)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("scan path escapes the configured root through a symlink")
	}
	return resolvedTarget, nil
}
