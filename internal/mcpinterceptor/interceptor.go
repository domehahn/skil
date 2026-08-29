package mcpinterceptor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/domehahn/skil/internal/mcpassure"
)

type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   any             `json:"error,omitempty"`
}

type InterceptorOptions struct {
	SurfaceLockPath string
	Strict          bool
}

type Interceptor struct {
	options     InterceptorOptions
	surfaceLock *mcpassure.SurfaceLock
}

func NewInterceptor(opts InterceptorOptions) (*Interceptor, error) {
	var lock *mcpassure.SurfaceLock
	if opts.SurfaceLockPath != "" {
		data, err := os.ReadFile(opts.SurfaceLockPath)
		if err == nil {
			var loaded mcpassure.SurfaceLock
			if err := json.Unmarshal(data, &loaded); err == nil {
				lock = &loaded
			}
		}
	}
	return &Interceptor{
		options:     opts,
		surfaceLock: lock,
	}, nil
}

func (i *Interceptor) FilterMessage(data []byte, fromClient bool) ([]byte, error) {
	var msg JSONRPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return data, nil
	}

	// 1. Intercept client tool invocation (method: tools/call)
	if fromClient && msg.Method == "tools/call" {
		var params struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(msg.Params, &params)

		if i.surfaceLock != nil && len(i.surfaceLock.Tools) > 0 {
			_, allowed := i.surfaceLock.Tools[params.Name]
			if !allowed && i.options.Strict {
				errResp := JSONRPCMessage{
					JSONRPC: "2.0",
					ID:      msg.ID,
					Error: map[string]any{
						"code":    -32601,
						"message": fmt.Sprintf("[skil] BLOCKED: Dynamic MCP Tool %q is not authorized in surface lock", params.Name),
					},
				}
				return json.Marshal(errResp)
			}
		}
	}

	return data, nil
}

func (i *Interceptor) RunStream(in io.Reader, out io.Writer, fromClient bool) error {
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Bytes()
		filtered, err := i.FilterMessage(line, fromClient)
		if err != nil {
			return err
		}
		if _, err := out.Write(append(filtered, '\n')); err != nil {
			return err
		}
	}
	return scanner.Err()
}
