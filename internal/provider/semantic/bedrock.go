package semantic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/domehahn/skil/pkg/skil"
)

const defaultBedrockRegion = "us-west-2"

type bedrockRuntimeClient interface {
	InvokeModel(context.Context, *bedrockruntime.InvokeModelInput, ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error)
}

type BedrockConfig struct {
	Model          string
	Region         string
	Client         bedrockRuntimeClient
	ValidationMode skil.SemanticValidationMode
}

// BedrockProvider invokes Anthropic Messages through the official AWS SDK.
// SigV4 credentials come from the standard SDK chain and are never exposed to
// scanned content or a child process.
type BedrockProvider struct {
	model          string
	region         string
	client         bedrockRuntimeClient
	validationMode skil.SemanticValidationMode
}

func NewBedrock(ctx context.Context, config BedrockConfig) (*BedrockProvider, error) {
	if config.Model == "" {
		return nil, errors.New("semantic model is required")
	}
	validationMode, err := validateSemanticMode(config.ValidationMode)
	if err != nil {
		return nil, err
	}
	if config.Region == "" {
		config.Region = defaultBedrockRegion
	}
	client := config.Client
	if client == nil {
		awsConfiguration, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(config.Region))
		if err != nil {
			return nil, fmt.Errorf("load AWS configuration: %w", err)
		}
		client = bedrockruntime.NewFromConfig(awsConfiguration)
	}
	return &BedrockProvider{model: config.Model, region: config.Region, client: client,
		validationMode: validationMode}, nil
}

func (p *BedrockProvider) ID() string { return "aws-bedrock/" + p.region + "/" + p.model }

func (p *BedrockProvider) AnalyzeUntrusted(ctx context.Context, request skil.SemanticRequest) ([]skil.Finding, error) {
	result, err := p.AnalyzeUntrustedDetailed(ctx, request)
	return result.Findings, err
}

func (p *BedrockProvider) AnalyzeUntrustedDetailed(ctx context.Context, request skil.SemanticRequest) (skil.SemanticAnalysis, error) {
	if !request.NoTools {
		return skil.SemanticAnalysis{}, errors.New("semantic analysis requires NoTools=true")
	}
	untrusted, err := json.Marshal(request)
	if err != nil {
		return skil.SemanticAnalysis{}, err
	}
	body, err := json.Marshal(map[string]any{
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens":        4096,
		"temperature":       0,
		"system":            semanticSystemPrompt + "\nReturn a JSON object with a findings array and no surrounding prose.",
		"messages": []map[string]string{{
			"role": "user", "content": "<UNTRUSTED_SKILL_DATA>\n" + string(untrusted) + "\n</UNTRUSTED_SKILL_DATA>",
		}},
	})
	if err != nil {
		return skil.SemanticAnalysis{}, err
	}
	contentType := "application/json"
	response, err := p.client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId: aws.String(p.model), Body: body, ContentType: &contentType, Accept: &contentType,
	})
	if err != nil {
		return degradedResult(fmt.Sprintf("bedrock semantic provider request failed: %v", err)), nil
	}
	if len(response.Body) > maxResponse {
		return degradedResult("semantic response exceeds size limit"), nil
	}
	var decoded struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(response.Body, &decoded); err != nil {
		return degradedResult("bedrock returned an invalid response"), nil
	}
	if decoded.StopReason == "max_tokens" {
		return degradedResult("bedrock semantic provider truncated its response (stop_reason=max_tokens); output token limit reached before completion"), nil
	}
	text := ""
	for _, block := range decoded.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}
	var result semanticResult
	if text == "" || json.Unmarshal([]byte(text), &result) != nil {
		return degradedResult("bedrock returned invalid structured output"), nil
	}
	if len(result.Findings) > 100 {
		return degradedResult("semantic provider returned too many findings"), nil
	}
	return normalizeFindingsDetailed(result.Findings, request, p.ID(), p.validationMode)
}
