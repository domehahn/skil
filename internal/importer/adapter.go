package importer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// ExternalFindingReport represents a generic JSON report from an external scanner
// adapter before normalization into SKIL's canonical evidence model.
type ExternalFindingReport struct {
	Producer        string                `json:"producer"`
	ProducerVersion string                `json:"producer_version"`
	SubjectDigest   string                `json:"subject_digest"`
	Findings        []ExternalFindingItem `json:"findings"`
}

type ExternalFindingItem struct {
	ID       string `json:"id"`
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// NormalizedExternalEvidence binds imported external findings to the exact
// artifact subject digest, preserves raw severity normalization provenance, and
// pins VerificationState to EvidenceObserved so unverified external reports
// never overwrite native EvidenceVerified proof.
type NormalizedExternalEvidence struct {
	Producer          string             `json:"producer"`
	ProducerVersion   string             `json:"producer_version"`
	SubjectDigest     string             `json:"subject_digest"`
	RawPayloadDigest  string             `json:"raw_payload_digest"`
	VerificationState skil.EvidenceState `json:"verification_state"`
	MaximumSeverity   skil.Severity      `json:"maximum_severity"`
	Findings          []skil.Finding     `json:"findings"`
}

// NormalizeExternalReport validates and normalizes an external scanner JSON report.
func NormalizeExternalReport(raw []byte, artifact skil.Artifact) (NormalizedExternalEvidence, error) {
	if artifact.SubjectDigest() == "" {
		return NormalizedExternalEvidence{}, errors.New("artifact subject digest is required for external adapter import")
	}
	var rep ExternalFindingReport
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		return NormalizedExternalEvidence{}, fmt.Errorf("parse external scanner report: %w", err)
	}
	if strings.TrimSpace(rep.Producer) == "" || strings.TrimSpace(rep.ProducerVersion) == "" {
		return NormalizedExternalEvidence{}, errors.New("external scanner report requires producer and producer_version")
	}
	if strings.TrimSpace(rep.SubjectDigest) != artifact.SubjectDigest() {
		return NormalizedExternalEvidence{}, fmt.Errorf("external report subject digest %q does not match artifact %q", rep.SubjectDigest, artifact.SubjectDigest())
	}

	rawSum := sha256.Sum256(raw)
	out := NormalizedExternalEvidence{
		Producer:          rep.Producer,
		ProducerVersion:   rep.ProducerVersion,
		SubjectDigest:     artifact.SubjectDigest(),
		RawPayloadDigest:  "sha256:" + hex.EncodeToString(rawSum[:]),
		VerificationState: skil.EvidenceObserved,
		MaximumSeverity:   skil.SeverityInfo,
	}
	if len(rep.Findings) == 0 {
		out.MaximumSeverity = ""
	}
	for i, item := range rep.Findings {
		if strings.TrimSpace(item.RuleID) == "" || strings.TrimSpace(item.File) == "" {
			return NormalizedExternalEvidence{}, fmt.Errorf("external finding[%d] requires rule_id and file", i)
		}
		norm := skil.NormalizeSeverity(item.Severity)
		if skil.SeverityRank(norm.Canonical) > skil.SeverityRank(out.MaximumSeverity) {
			out.MaximumSeverity = norm.Canonical
		}
		line := item.Line
		if line <= 0 {
			line = 1
		}
		f := skil.Finding{
			ID:       item.ID,
			RuleID:   "EXTERNAL-" + strings.ToUpper(rep.Producer) + "-" + item.RuleID,
			Title:    item.Title,
			Category: "external-scanner",
			Severity: norm.Canonical,
			Message:  item.Message,
			Location: skil.Location{File: item.File, StartLine: line, EndLine: line},
			Evidence: map[string]any{
				"external_producer":         rep.Producer,
				"external_producer_version": rep.ProducerVersion,
				"raw_severity":              norm.Original,
				"severity_known":            norm.Known,
				"verification_state":        string(skil.EvidenceObserved),
			},
		}
		out.Findings = append(out.Findings, f)
	}
	return out, nil
}
