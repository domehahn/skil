package evaltestadapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestRunRequestsThenCompletesMediatedTool(t *testing.T) {
	request := func(exchange skil.GatewayExchange) skil.GatewayMessage {
		t.Helper()
		var input, output bytes.Buffer
		if err := json.NewEncoder(&input).Encode(exchange); err != nil {
			t.Fatal(err)
		}
		if err := Run(&input, &output); err != nil {
			t.Fatal(err)
		}
		var message skil.GatewayMessage
		if err := json.NewDecoder(&output).Decode(&message); err != nil {
			t.Fatal(err)
		}
		return message
	}
	first := request(skil.GatewayExchange{Version: 1})
	if first.Type != "tool_call" || first.Tool != "containment.simulate" || first.ID != requestID {
		t.Fatalf("unexpected first message: %#v", first)
	}
	final := request(skil.GatewayExchange{Version: 1, Results: []skil.GatewayResult{
		{ID: requestID, Result: map[string]any{"answer": "bounded"}},
	}})
	if final.Type != "final" || final.Final == nil || len(final.Final.Outputs) != 1 {
		t.Fatalf("unexpected final message: %#v", final)
	}
}

func TestRunFailsClosedForMalformedOrDeniedExchange(t *testing.T) {
	for _, input := range []string{
		`{"version":2,"request":{},"results":[]}`,
		`{"version":1,"request":{},"results":[{"id":"assurance-e2e-1","denied":true}]}`,
		`{"version":1,"request":{},"results":[]} {}`,
	} {
		if err := Run(strings.NewReader(input), &bytes.Buffer{}); err == nil {
			t.Errorf("unsafe exchange accepted: %s", input)
		}
	}
}
