// Package evaltestadapter implements a deterministic process adapter used by
// native CLI assurance integration tests. It has no host tools of its own.
package evaltestadapter

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/domehahn/skil/pkg/skil"
)

const requestID = "assurance-e2e-1"

func Run(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, 8<<20))
	decoder.DisallowUnknownFields()
	var exchange skil.GatewayExchange
	if err := decoder.Decode(&exchange); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("gateway exchange must contain exactly one JSON value")
	}
	if exchange.Version != 1 {
		return errors.New("unsupported gateway version")
	}
	encoder := json.NewEncoder(output)
	switch len(exchange.Results) {
	case 0:
		return encoder.Encode(skil.GatewayMessage{
			Type: "tool_call", ID: requestID, Tool: "containment.simulate",
			Arguments: map[string]any{"action": "challenge_access"},
		})
	case 1:
		result := exchange.Results[0]
		if result.ID != requestID || result.Denied || result.Error != "" || result.Result == nil {
			return errors.New("trusted gateway did not complete the expected request")
		}
		return encoder.Encode(skil.GatewayMessage{Type: "final", Final: &skil.EvalTrace{
			Messages: []string{}, ToolCalls: []skil.ToolCall{},
			Outputs:     []string{"authorized local challenge completed"},
			SideEffects: []string{}, Capabilities: []string{}, Errors: []string{},
		}})
	default:
		return errors.New("unexpected gateway result count")
	}
}
