package external

import (
	"context"
	"fmt"

	"github.com/domehahn/skil/pkg/skil"
)

// ProviderCapabilities advertises supported analysis domains of an external engine.
type ProviderCapabilities struct {
	Name         string   `json:"name" yaml:"name"`
	Version      string   `json:"version" yaml:"version"`
	Capabilities []string `json:"capabilities" yaml:"capabilities"` // e.g. ["security", "quality", "evaluation"]
}

// ExternalSecurityProvider defines the interface for third-party security scanners.
type ExternalSecurityProvider interface {
	Name() string
	Capabilities() ProviderCapabilities
	Scan(ctx context.Context, art *skil.Artifact) ([]skil.Finding, error)
}

// ExternalEvaluatorProvider defines the interface for third-party evaluation engines (garak, promptfoo, NeMo).
type ExternalEvaluatorProvider interface {
	Name() string
	Capabilities() ProviderCapabilities
	Evaluate(ctx context.Context, art *skil.Artifact) (skillLift float64, passAtK float64, err error)
}

// NormalizedExternalFinding converts a raw external provider payload into a canonical SKIL finding.
func NormalizedExternalFinding(providerName, rawRuleID, category string, severity skil.Severity, confidence float64, title, message, file string, startLine int) skil.Finding {
	ruleID := fmt.Sprintf("%s-%s", providerName, rawRuleID)
	return skil.Finding{
		ID:         ruleID,
		RuleID:     ruleID,
		Category:   category,
		Severity:   severity,
		Confidence: confidence,
		Title:      title,
		Message:    message,
		Location: skil.Location{
			File:      file,
			StartLine: startLine,
		},
		Evidence: map[string]any{
			"provider": providerName,
			"raw_rule": rawRuleID,
		},
		Fingerprint: fmt.Sprintf("%s-%s-%s-%d", providerName, rawRuleID, file, startLine),
	}
}

// MockExternalProvider is an offline mock implementation for testing external adapter orchestration.
type MockExternalProvider struct {
	ProviderName string
	MockFindings []skil.Finding
	MockLift     float64
	MockPassAtK  float64
}

func (m *MockExternalProvider) Name() string {
	return m.ProviderName
}

func (m *MockExternalProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{
		Name:         m.ProviderName,
		Version:      "1.0.0",
		Capabilities: []string{"security", "evaluation"},
	}
}

func (m *MockExternalProvider) Scan(ctx context.Context, art *skil.Artifact) ([]skil.Finding, error) {
	return m.MockFindings, nil
}

func (m *MockExternalProvider) Evaluate(ctx context.Context, art *skil.Artifact) (float64, float64, error) {
	return m.MockLift, m.MockPassAtK, nil
}
