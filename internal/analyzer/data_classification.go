package analyzer

import (
	"context"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

// DataClassification covers the ASP-03 (privacy/confidentiality) properties
// the generic Taint engine does not model: it tracks source→sink data flow
// as capability categories, not data sensitivity. Here a data flow entry
// carries a sensitivity label (credential/pii/health/financial/secret) plus
// the purpose it was collected for, and three structural properties are
// checked against it: the sink's purpose must match the source's declared
// purpose (purpose limitation), sensitive data must not be retained
// indefinitely (retention minimization), and a sensitive-labeled flow must
// not collect an unconstrained "all fields" superset (data minimization).
type DataClassification struct{}

func NewDataClassification() *DataClassification { return &DataClassification{} }

var sensitiveDataLabels = map[string]bool{
	"credential": true, "pii": true, "health": true, "financial": true, "secret": true,
}

var unboundedRetentionValues = map[string]bool{
	"indefinite": true, "forever": true, "unbounded": true, "never": true, "permanent": true,
}

func (d *DataClassification) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.data-classification", Version: "1.0.0",
		Domain: "data-dataset", Subdomain: "pii",
		Categories:    []string{"data-privacy"},
		AnalysisTypes: []string{"data-classification"}, SupportedTypes: []string{"*"}}
}

type dataFlowEntry struct {
	Label       string
	Purpose     string
	SinkPurpose string
	Retention   string
	Fields      any
}

func (d *DataClassification) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if !strings.Contains(string(file.Data), "data_flows") {
			continue
		}
		var document any
		if err := yaml.Unmarshal(file.Data, &document); err != nil || !isStructuredMCPDocument(document) {
			continue
		}
		for _, entry := range collectDataFlows(document) {
			label := strings.ToLower(strings.TrimSpace(entry.Label))
			if !sensitiveDataLabels[label] {
				continue
			}
			if entry.SinkPurpose != "" && entry.Purpose != "" && !strings.EqualFold(entry.SinkPurpose, entry.Purpose) {
				line, text := lineContaining(file.Data, entry.SinkPurpose)
				out = append(out, makeFinding(RulePattern{Rule: skil.Rule{
					ID: "SKIL-DATA-PURPOSE-VIOLATION", Title: "Purpose limitation violation",
					Category: "data-privacy", Severity: skil.SeverityCritical,
					Description: label + "-labeled data collected for \"" + entry.Purpose + "\" is used for the unrelated purpose \"" + entry.SinkPurpose + "\".",
					Analysis:    "data-classification", Remediation: "Use sensitive data only for the purpose it was collected for; re-request consent before repurposing it.",
				}, Confidence: .9}, file, line, text))
			}
			if unboundedRetentionValues[strings.ToLower(strings.TrimSpace(entry.Retention))] {
				line, text := lineContaining(file.Data, entry.Retention)
				out = append(out, makeFinding(RulePattern{Rule: skil.Rule{
					ID: "SKIL-DATA-RETENTION-UNBOUNDED", Title: "Unbounded sensitive data retention",
					Category: "data-privacy", Severity: skil.SeverityHigh,
					Description: label + "-labeled data is retained with no expiration (\"" + entry.Retention + "\"), increasing the blast radius of any future breach.",
					Analysis:    "data-classification", Remediation: "Set an explicit, minimal retention period for sensitive data and delete it once that period elapses.",
				}, Confidence: .9}, file, line, text))
			}
			if containsWildcard(entry.Fields) {
				line, text := lineContaining(file.Data, "fields")
				out = append(out, makeFinding(RulePattern{Rule: skil.Rule{
					ID: "SKIL-DATA-OVERBROAD-COLLECTION", Title: "Sensitive data minimization violation",
					Category: "data-privacy", Severity: skil.SeverityHigh,
					Description: label + "-labeled data collection declares an unconstrained field set rather than the minimum fields the purpose needs.",
					Analysis:    "data-classification", Remediation: "Enumerate only the specific fields the declared purpose requires; never collect an unconstrained superset.",
				}, Confidence: .9}, file, line, text))
			}
		}
	}
	return out, nil
}

// collectDataFlows recognizes any YAML/JSON document with a "data_flows"
// list of maps, each optionally declaring label, purpose, sink_purpose,
// retention, and fields.
func collectDataFlows(value any) []dataFlowEntry {
	var out []dataFlowEntry
	var visit func(any)
	visit = func(v any) {
		switch item := v.(type) {
		case map[string]any:
			if flows, ok := item["data_flows"].([]any); ok {
				for _, flow := range flows {
					m, ok := flow.(map[string]any)
					if !ok {
						continue
					}
					out = append(out, dataFlowEntry{
						Label:       stringValue(m["label"]),
						Purpose:     stringValue(m["purpose"]),
						SinkPurpose: stringValue(m["sink_purpose"]),
						Retention:   stringValue(m["retention"]),
						Fields:      m["fields"],
					})
				}
			}
			for _, key := range sortedMapKeys(item) {
				visit(item[key])
			}
		case []any:
			for _, child := range item {
				visit(child)
			}
		}
	}
	visit(value)
	return out
}
