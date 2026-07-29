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
	Endpoint     string
	Model        string
	APIKey       string
	AllowPrivate bool
	HTTPClient   *http.Client
}

type AnthropicProvider struct {
	endpoint string
	model    string
	apiKey   string
	client   *http.Client
	bearer   bool
	proxy    bool
	version  string
}

func NewAnthropic(config AnthropicConfig) (*AnthropicProvider, error) {
	if config.Endpoint == "" {
		config.Endpoint = defaultAnthropicEndpoint
	}
	if config.Model == "" {
		return nil, errors.New("semantic model is required")
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
	return &AnthropicProvider{endpoint: config.Endpoint, model: config.Model, apiKey: config.APIKey, client: client}, nil
}

func (p *AnthropicProvider) ID() string { return "anthropic/" + p.model }

type AnthropicProxyConfig struct {
	Endpoint     string
	Model        string
	BearerToken  string
	APIVersion   string
	AllowPrivate bool
	HTTPClient   *http.Client
}

// NewAnthropicProxy supports Vertex-style raw-predict gateways while retaining
// the same SSRF, response-size, no-tools, and strict-output controls.
func NewAnthropicProxy(config AnthropicProxyConfig) (*AnthropicProvider, error) {
	if config.Endpoint == "" || config.BearerToken == "" {
		return nil, errors.New("anthropic proxy endpoint and bearer token are required")
	}
	provider, err := NewAnthropic(AnthropicConfig{
		Endpoint: config.Endpoint, Model: config.Model, APIKey: config.BearerToken,
		AllowPrivate: config.AllowPrivate, HTTPClient: config.HTTPClient,
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
	if !request.NoTools {
		return nil, errors.New("semantic analysis requires NoTools=true")
	}
	untrusted, err := json.Marshal(request)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("semantic provider request: %w", err)
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	_ = response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if len(responseBody) > maxResponse {
		return nil, errors.New("semantic response exceeds size limit")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("semantic provider returned HTTP %d", response.StatusCode)
	}
	var decoded struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return nil, errors.New("semantic provider returned an invalid response")
	}
	text := ""
	for _, block := range decoded.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}
	var result semanticResult
	if text == "" || json.Unmarshal([]byte(text), &result) != nil {
		return nil, errors.New("semantic provider returned invalid structured output")
	}
	if len(result.Findings) > 100 {
		return nil, errors.New("semantic provider returned too many findings")
	}
	return normalizeFindings(result.Findings, request, p.ID())
}
