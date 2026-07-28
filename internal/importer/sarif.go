// Package importer normalizes evidence produced by external scanners.
package importer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

type SARIF struct{}

func (SARIF) ID() string { return "sarif-2.1.0" }

type sarifDocument struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			Level      string         `json:"level"`
			Properties map[string]any `json:"properties"`
		} `json:"results"`
		Properties map[string]any `json:"properties"`
	} `json:"runs"`
}

func (SARIF) Import(_ context.Context, data []byte, artifact skil.Artifact) ([]skil.Evidence, error) {
	if artifact.SubjectDigest() == "" {
		return nil, errors.New("artifact digest is required before evidence import")
	}
	var document sarifDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse SARIF: %w", err)
	}
	if document.Version != "2.1.0" {
		return nil, fmt.Errorf("unsupported SARIF version %q", document.Version)
	}
	if len(document.Runs) == 0 {
		return nil, errors.New("SARIF contains no runs")
	}
	payload := sha256.Sum256(data)
	out := make([]skil.Evidence, 0, len(document.Runs))
	for _, run := range document.Runs {
		if run.Tool.Driver.Name == "" {
			return nil, errors.New("SARIF run has no tool identity")
		}
		subjectDigest := sarifSubjectDigest(run.Properties)
		if subjectDigest == "" {
			return nil, errors.New("SARIF run has no skil subject digest binding")
		}
		if subjectDigest != artifact.SubjectDigest() {
			return nil, fmt.Errorf("SARIF subject digest %q does not match artifact %q", subjectDigest, artifact.SubjectDigest())
		}
		maximum := skil.SeverityInfo
		for _, result := range run.Results {
			severity := sarifSeverity(result.Level, result.Properties)
			if severityRank(severity) > severityRank(maximum) {
				maximum = severity
			}
		}
		status := skil.StatusPass
		if maximum == skil.SeverityMedium || maximum == skil.SeverityLow {
			status = skil.StatusWarn
		}
		if severityRank(maximum) >= severityRank(skil.SeverityHigh) {
			status = skil.StatusFail
		}
		out = append(out, skil.Evidence{Type: "external-security-scan", Producer: run.Tool.Driver.Name,
			ProducerVer: run.Tool.Driver.Version, SubjectDigest: artifact.SubjectDigest(), Timestamp: time.Now().UTC(),
			PayloadDigest: hex.EncodeToString(payload[:]), Coverage: []string{"sarif"},
			Result: skil.EvidenceResult{Status: status, MaximumSeverity: maximum, Findings: len(run.Results)}})
	}
	return out, nil
}

func sarifSeverity(level string, properties map[string]any) skil.Severity {
	if value, ok := properties["severity"].(string); ok {
		switch skil.Severity(strings.ToUpper(value)) {
		case skil.SeverityCritical, skil.SeverityHigh, skil.SeverityMedium, skil.SeverityLow, skil.SeverityInfo:
			return skil.Severity(strings.ToUpper(value))
		}
	}
	switch strings.ToLower(level) {
	case "error":
		return skil.SeverityHigh
	case "warning":
		return skil.SeverityMedium
	case "note":
		return skil.SeverityLow
	default:
		return skil.SeverityInfo
	}
}

func severityRank(value skil.Severity) int {
	switch value {
	case skil.SeverityCritical:
		return 4
	case skil.SeverityHigh:
		return 3
	case skil.SeverityMedium:
		return 2
	case skil.SeverityLow:
		return 1
	default:
		return 0
	}
}

func sarifSubjectDigest(properties map[string]any) string {
	if value, ok := properties["skil_subject_digest"].(string); ok {
		return value
	}
	nested, ok := properties["skil"].(map[string]any)
	if !ok {
		return ""
	}
	value, _ := nested["subject_digest"].(string)
	return value
}
