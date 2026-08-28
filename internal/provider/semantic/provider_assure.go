package semantic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ProviderAssuranceResult struct {
	ProviderID          string           `json:"provider_id"`
	ConfiguredEndpoint  string           `json:"configured_endpoint"`
	TLSHostname         string           `json:"tls_hostname"`
	RequestedModel      string           `json:"requested_model"`
	ReportedModel       string           `json:"reported_model"`
	ProtocolCompatible  bool             `json:"protocol_compatible"`
	ConfigurationDigest string           `json:"configuration_digest"`
	Checks              []AssuranceCheck `json:"checks"`
	Passed              bool             `json:"passed"`
}

type AssuranceCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details,omitempty"`
}

// AssureProvider executes bounded, non-destructive assurance probes against a semantic provider.
func AssureProvider(ctx context.Context, p *Provider) (ProviderAssuranceResult, error) {
	if p == nil {
		return ProviderAssuranceResult{}, fmt.Errorf("provider is nil")
	}

	parsedURL, err := url.Parse(p.endpoint)
	if err != nil {
		return ProviderAssuranceResult{}, fmt.Errorf("invalid provider endpoint: %w", err)
	}

	var checks []AssuranceCheck
	passed := true

	// Check 1: Scheme and TLS
	tlsCheck := AssuranceCheck{Name: "tls_and_scheme", Status: "PASS"}
	if parsedURL.Scheme != "https" {
		tlsCheck.Status = "WARN"
		tlsCheck.Details = "endpoint does not use TLS (http)"
	}
	checks = append(checks, tlsCheck)

	// Check 2: Metadata host / redirect protection
	metaCheck := AssuranceCheck{Name: "host_boundary", Status: "PASS"}
	if isMetadataHost(parsedURL.Hostname()) {
		metaCheck.Status = "FAIL"
		metaCheck.Details = "cloud metadata endpoint target rejected"
		passed = false
	}
	checks = append(checks, metaCheck)

	// Check 3: Configuration Digest
	configBytes := []byte(fmt.Sprintf("%s|%s|%s", p.endpoint, p.model, p.validationMode))
	sum := sha256.Sum256(configBytes)
	configDigest := "sha256:" + hex.EncodeToString(sum[:])

	// Check 4: Non-destructive ping probe (if HTTP client is provided)
	reportedModel := p.model
	protocolCompatible := true

	if p.client != nil {
		pingBody, _ := json.Marshal(map[string]any{
			"model":       p.model,
			"messages":    []map[string]string{{"role": "user", "content": "skil-assurance-probe"}},
			"max_tokens":  5,
			"temperature": 0,
		})

		req, err := http.NewRequestWithContext(ctx, "POST", p.endpoint, bytes.NewReader(pingBody))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			if p.apiKey != "" {
				req.Header.Set("Authorization", "Bearer "+p.apiKey)
			}
			ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			req = req.WithContext(ctxTimeout)

			resp, err := p.client.Do(req)
			if err != nil {
				checks = append(checks, AssuranceCheck{
					Name:    "live_probe",
					Status:  "WARN",
					Details: fmt.Sprintf("probe connection failed: %v", err),
				})
			} else {
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					var raw map[string]any
					if err := json.NewDecoder(resp.Body).Decode(&raw); err == nil {
						if modelVal, ok := raw["model"].(string); ok && modelVal != "" {
							reportedModel = modelVal
						}
					}
					checks = append(checks, AssuranceCheck{Name: "live_probe", Status: "PASS", Details: fmt.Sprintf("HTTP %d", resp.StatusCode)})
				} else {
					protocolCompatible = false
					checks = append(checks, AssuranceCheck{Name: "live_probe", Status: "WARN", Details: fmt.Sprintf("HTTP %d", resp.StatusCode)})
				}
			}
		}
	}

	// Model identity consistency check
	modelCheck := AssuranceCheck{Name: "model_identity_consistency", Status: "PASS"}
	if !strings.EqualFold(p.model, reportedModel) && !strings.Contains(strings.ToLower(reportedModel), strings.ToLower(p.model)) {
		modelCheck.Status = "WARN"
		modelCheck.Details = fmt.Sprintf("requested model %q differs from reported model %q", p.model, reportedModel)
	}
	checks = append(checks, modelCheck)

	return ProviderAssuranceResult{
		ProviderID:          p.ID(),
		ConfiguredEndpoint:  p.endpoint,
		TLSHostname:         parsedURL.Hostname(),
		RequestedModel:      p.model,
		ReportedModel:       reportedModel,
		ProtocolCompatible:  protocolCompatible,
		ConfigurationDigest: configDigest,
		Checks:              checks,
		Passed:              passed,
	}, nil
}
