package semantic

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/domehahn/skil/pkg/skil"
)

type fakeBedrockClient struct {
	input *bedrockruntime.InvokeModelInput
}

func (f *fakeBedrockClient) InvokeModel(_ context.Context, input *bedrockruntime.InvokeModelInput,
	_ ...func(*bedrockruntime.Options),
) (*bedrockruntime.InvokeModelOutput, error) {
	f.input = input
	finding := `{"findings":[{"control":"semantic_security","severity":"HIGH","confidence":0.9,"title":"Risk","message":"Risk","file":"SKILL.md","start_line":1,"end_line":1,"remediation":"Fix"}]}`
	body, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": finding}}})
	return &bedrockruntime.InvokeModelOutput{Body: body}, nil
}

func TestBedrockUsesNativeToollessMessagesContract(t *testing.T) {
	client := &fakeBedrockClient{}
	provider, err := NewBedrock(context.Background(), BedrockConfig{
		Model: "anthropic.test", Region: "eu-central-1", Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := provider.AnalyzeUntrusted(context.Background(), skil.SemanticRequest{
		Focus: "security", NoTools: true, Files: map[string]string{"SKILL.md": "unsafe"},
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("Bedrock analysis failed: %v %#v", err, findings)
	}
	var payload map[string]any
	if err := json.Unmarshal(client.input.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["anthropic_version"] != "bedrock-2023-05-31" || payload["tools"] != nil {
		t.Fatalf("unexpected Bedrock payload: %#v", payload)
	}
}
