package analyzer

import (
	"context"

	"github.com/domehahn/skil/pkg/skil"
)

type DataDataset struct{}

func NewDataDataset() *DataDataset { return &DataDataset{} }

func (a *DataDataset) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.data-dataset", Version: "1.0.0",
		Domain: "data-dataset", Subdomain: "poisoning",
		Categories:    []string{"data-security"},
		AnalysisTypes: []string{"data-dataset"}, SupportedTypes: []string{"*"}}
}

func (a *DataDataset) TaxonomyDomain() string    { return "data-dataset" }
func (a *DataDataset) TaxonomySubdomain() string { return "poisoning" }
func (a *DataDataset) ControlIDs() []string {
	return []string{"DATA-001", "DATA-002", "DATA-003", "DATA-004", "DATA-005"}
}

func (a *DataDataset) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	return nil, nil
}
