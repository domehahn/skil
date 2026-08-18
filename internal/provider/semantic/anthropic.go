package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

const defaultAnthropicEndpoint = "https://api.anthropic.com/v1/messages"

type AnthropicConfig struct {
	Endpoint       string
	Model          string
	APIKey         string
	AllowPrivate   bool
	HTTPClient     *http.Client
	ValidationMode skil.SemanticValidationMode
}

type AnthropicProvider struct {
	endpoint       string
	model          string
	apiKey         string
	client         *http.Client
	bearer         bool
	proxy          bool
	version        string
	validationMode skil.SemanticValidationMode
}

func NewAnthropic(config AnthropicConfig) (*AnthropicProvider, error) {
	if config.Endpoint == "" {
		config.Endpoint = defaultAnthropicEndpoint
	}
	if config.Model == "" {
		return nil, errors.New("semantic model is required")
	}
	validationMode, err := validateSemanticMode(config.ValidationMode)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") ||
		parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("semantic endpoint must be an http(s) URL without credentials or fragment")
	}
	if isMetadataHost(parsed.Hostname()) {
		return nil, errors.New("cloud metadata endpoints are prohibited")
	}
	client := config.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = http.ProxyFromEnvironment
		transport.DialContext = safeDialer(config.AllowPrivate)
		client = &http.Client{Transport: transport, Timeout: 60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("semantic endpoint redirects are disabled")
			}}
	}
	return &AnthropicProvider{endpoint: config.Endpoint, model: config.Model, apiKey: config.APIKey,
		client: client, validationMode: validationMode}, nil
}

func (p *AnthropicProvider) ID() string { return "anthropic/" + p.model }

type AnthropicProxyConfig struct {
	Endpoint       string
	Model          string
	BearerToken    string
	APIVersion     string
	AllowPrivate   bool
	HTTPClient     *http.Client
	ValidationMode skil.SemanticValidationMode
}

// NewAnthropicProxy supports Vertex-style raw-predict gateways while retaining
// the same SSRF, response-size, no-tools, and strict-output controls.
func NewAnthropicProxy(config AnthropicProxyConfig) (*AnthropicProvider, error) {
	if config.Endpoint == "" || config.BearerToken == "" {
		return nil, errors.New("anthropic proxy endpoint and bearer token are required")
	}
	provider, err := NewAnthropic(AnthropicConfig{
		Endpoint: config.Endpoint, Model: config.Model, APIKey: config.BearerToken,
		AllowPrivate: config.AllowPrivate, HTTPClient: config.HTTPClient, ValidationMode: config.ValidationMode,
	})
	if err != nil {
		return nil, err
	}
	if config.APIVersion == "" {
		config.APIVersion = "vertex-2023-10-16"
	}
	provider.bearer, provider.proxy, provider.version = true, true, config.APIVersion
	return provider, nil
}

func (p *AnthropicProvider) AnalyzeUntrusted(ctx context.Context, request skil.SemanticRequest) ([]skil.Finding, error) {
	result, err := p.AnalyzeUntrustedDetailed(ctx, request)
	return result.Findings, err
}

func (p *AnthropicProvider) AnalyzeUntrustedDetailed(ctx context.Context, request skil.SemanticRequest) (skil.SemanticAnalysis, error) {
	if !request.NoTools {
		return skil.SemanticAnalysis{}, errors.New("semantic analysis requires NoTools=true")
	}
	untrusted, err := json.Marshal(request)
	if err != nil {
		return skil.SemanticAnalysis{}, err
	}
	payload := map[string]any{
		"model": p.model, "max_tokens": 4096, "temperature": 0,
		"system": semanticSystemPrompt + "\nReturn a JSON object with a findings array and no surrounding prose.",
		"messages": []map[string]string{{
			"role": "user", "content": "<UNTRUSTED_SKILL_DATA>\n" + string(untrusted) + "\n</UNTRUSTED_SKILL_DATA>",
		}},
	}
	if p.proxy {
		delete(payload, "model")
		payload["anthropic_version"] = p.version
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return skil.SemanticAnalysis{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return skil.SemanticAnalysis{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("User-Agent", "skil/"+skil.Version)
	if !p.proxy {
		httpRequest.Header.Set("Anthropic-Version", "2023-06-01")
	}
	if p.apiKey != "" {
		if p.bearer {
			httpRequest.Header.Set("Authorization", "Bearer "+p.apiKey)
		} else {
			httpRequest.Header.Set("X-Api-Key", p.apiKey)
		}
	}
	response, err := p.client.Do(httpRequest)
	if err != nil {
		return skil.SemanticAnalysis{}, fmt.Errorf("semantic provider request: %w", err)
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	_ = response.Body.Close()
	if readErr != nil {
		return skil.SemanticAnalysis{}, readErr
	}
	if len(responseBody) > maxResponse {
		return skil.SemanticAnalysis{}, errors.New("semantic response exceeds size limit")
	}
	if response.StatusCode != http.StatusOK {
		return skil.SemanticAnalysis{}, fmt.Errorf("semantic provider returned HTTP %d", response.StatusCode)
	}
	var decoded struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return skil.SemanticAnalysis{}, errors.New("semantic provider returned an invalid response")
	}
	text := ""
	for _, block := range decoded.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}
	var result semanticResult
	if text == "" || json.Unmarshal([]byte(text), &result) != nil {
		return skil.SemanticAnalysis{}, errors.New("semantic provider returned invalid structured output")
	}
	if len(result.Findings) > 100 {
		return skil.SemanticAnalysis{}, errors.New("semantic provider returned too many findings")
	}
	return normalizeFindingsDetailed(result.Findings, request, p.ID(), p.validationMode)
}
