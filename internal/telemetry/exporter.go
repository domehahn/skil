package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/domehahn/skil/internal/trust"
	"github.com/domehahn/skil/pkg/skil"
)

// OTelSpanFormat represents a structured OpenTelemetry audit span.
type OTelSpanFormat struct {
	TraceID    string                 `json:"trace_id" yaml:"trace_id"`
	SpanID     string                 `json:"span_id" yaml:"span_id"`
	Name       string                 `json:"name" yaml:"name"`
	Kind       string                 `json:"kind" yaml:"kind"`
	StartTime  time.Time              `json:"start_time" yaml:"start_time"`
	EndTime    time.Time              `json:"end_time" yaml:"end_time"`
	Attributes map[string]interface{} `json:"attributes" yaml:"attributes"`
	StatusCode string                 `json:"status_code" yaml:"status_code"`
}

// OTelTraceBatch aggregates spans for export to SIEM / collectors.
type OTelTraceBatch struct {
	ResourceAttributes map[string]string `json:"resource_attributes" yaml:"resource_attributes"`
	Spans              []OTelSpanFormat  `json:"spans" yaml:"spans"`
}

// BuildTrustTraceSpan constructs an OTel span from a Skill Trust Assessment.
func BuildTrustTraceSpan(assessment trust.TrustAssessment) OTelSpanFormat {
	seed := fmt.Sprintf("%s:%s:%d", assessment.ArtifactName, assessment.Digest, assessment.Timestamp.UnixNano())
	hash := sha256.Sum256([]byte(seed))
	hashHex := hex.EncodeToString(hash[:])

	traceID := fmt.Sprintf("skil-trace-%s", hashHex[:16])
	spanID := fmt.Sprintf("span-%s", hashHex[16:24])

	attrs := map[string]interface{}{
		"skill.name":         assessment.ArtifactName,
		"skill.version":      assessment.Version,
		"skill.digest":       assessment.Digest,
		"trust.score":        assessment.TrustScore.Score,
		"trust.level":        string(assessment.TrustLevel),
		"admission.decision": string(assessment.AdmissionDecision),
	}

	return OTelSpanFormat{
		TraceID:    traceID,
		SpanID:     spanID,
		Name:       fmt.Sprintf("skil.trust.eval.%s", assessment.ArtifactName),
		Kind:       "INTERNAL",
		StartTime:  assessment.Timestamp,
		EndTime:    assessment.Timestamp.Add(50 * time.Millisecond),
		Attributes: attrs,
		StatusCode: "OK",
	}
}

// ExportTraceBatch formats spans as OTLP JSON.
func ExportTraceBatch(spans []OTelSpanFormat) ([]byte, error) {
	ver := skil.Version
	if ver == "" {
		ver = "0.6.0"
	}

	batch := OTelTraceBatch{
		ResourceAttributes: map[string]string{
			"service.name":    "skil-agent-governance",
			"service.version": ver,
		},
		Spans: spans,
	}

	return json.MarshalIndent(batch, "", "  ")
}
