package report

import (
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type SarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}
type SarifRun struct {
	Tool       SarifTool      `json:"tool"`
	Results    []SarifResult  `json:"results"`
	Artifacts  []any          `json:"artifacts,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}
type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}
type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}
type SarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription SarifMessage   `json:"shortDescription"`
	FullDescription  SarifMessage   `json:"fullDescription"`
	Help             SarifMessage   `json:"help"`
	Properties       map[string]any `json:"properties"`
}
type SarifMessage struct {
	Text string `json:"text"`
}
type SarifResult struct {
	RuleID              string              `json:"ruleId"`
	Level               string              `json:"level"`
	Message             SarifMessage        `json:"message"`
	Locations           []SarifLocation     `json:"locations,omitempty"`
	PartialFingerprints map[string]string   `json:"partialFingerprints"`
	Suppressions        []map[string]string `json:"suppressions,omitempty"`
}
type SarifLocation struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region,omitempty"`
}
type ArtifactLocation struct {
	URI string `json:"uri"`
}
type Region struct {
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
}

func SARIF(scan skil.ScanResult) SarifLog {
	rules := map[string]SarifRule{}
	results := make([]SarifResult, 0, len(scan.Findings))
	for _, f := range scan.Findings {
		ruleID := safeDisplay(f.RuleID)
		rules[ruleID] = SarifRule{ID: ruleID, Name: safeDisplay(f.Title),
			ShortDescription: SarifMessage{safeDisplay(f.Title)}, FullDescription: SarifMessage{safeDisplay(f.Description)},
			Help: SarifMessage{safeDisplay(f.Remediation)}, Properties: map[string]any{"category": safeDisplay(f.Category), "security-severity": severityScore(f.Severity)}}
		result := SarifResult{RuleID: ruleID, Level: sarifLevel(f.Severity), Message: SarifMessage{safeDisplay(f.Message)},
			PartialFingerprints: map[string]string{"primaryLocationLineHash": f.Fingerprint}}
		if f.Location.File != "" {
			result.Locations = []SarifLocation{{PhysicalLocation{ArtifactLocation{safeDisplay(f.Location.File)}, Region{f.Location.StartLine, f.Location.EndLine}}}}
		}
		if f.Suppressed {
			suppression := map[string]string{"kind": "external", "status": "accepted"}
			if f.SuppressionReason != "" {
				suppression["justification"] = safeDisplay(f.SuppressionReason)
			}
			result.Suppressions = []map[string]string{suppression}
		}
		results = append(results, result)
	}
	ruleList := make([]SarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	return SarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SarifRun{{Tool: SarifTool{SarifDriver{Name: "skil", Version: skil.Version,
			InformationURI: "https://github.com/domehahn/skil", Rules: ruleList}}, Results: results,
			Properties: map[string]any{"skil": map[string]any{
				"subject_digest": scan.Artifact.Digest, "subject_name": scan.Artifact.Name,
				"subject_version": scan.Artifact.Version, "inspection_summary": scan.Completeness,
			}}}}}
}
func sarifLevel(s skil.Severity) string {
	switch s {
	case skil.SeverityCritical, skil.SeverityHigh:
		return "error"
	case skil.SeverityMedium, skil.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}
func severityScore(s skil.Severity) string {
	return map[skil.Severity]string{skil.SeverityCritical: "9.5", skil.SeverityHigh: "8.0", skil.SeverityMedium: "5.5", skil.SeverityLow: "2.0", skil.SeverityInfo: "0.0"}[s]
}

var _ = strings.Builder{}
