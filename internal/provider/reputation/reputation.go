package reputation

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
	"github.com/domehahn/skil/schemas"
)

type Document struct {
	Version    int         `json:"version"`
	Provenance *Provenance `json:"provenance,omitempty"`
	Packages   []Record    `json:"packages"`
}

type Provenance struct {
	Source     string    `json:"source"`
	ReviewedAt time.Time `json:"reviewed_at"`
	Evidence   string    `json:"evidence"`
}

type Record struct {
	Ecosystem  string    `json:"ecosystem"`
	Name       string    `json:"name"`
	Abandoned  bool      `json:"abandoned"`
	LastUpdate time.Time `json:"last_update,omitempty"`
}

type Provider struct {
	records map[string]skil.PackageReputation
}

//go:embed builtin-v1.json
var builtinEvidence []byte

func Load(path string) (*Provider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return load(data, false)
}

func LoadBuiltin() (*Provider, error) {
	return load(builtinEvidence, true)
}

func load(data []byte, requireProvenance bool) (*Provider, error) {
	if err := schemas.ValidateYAML("dependency-reputation-v1.schema.json", data); err != nil {
		return nil, err
	}
	var document Document
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode dependency reputation evidence: %w", err)
	}
	if document.Version != 1 || len(document.Packages) == 0 {
		return nil, fmt.Errorf("dependency reputation evidence requires version 1 and packages")
	}
	if requireProvenance && (document.Provenance == nil || strings.TrimSpace(document.Provenance.Source) == "" ||
		document.Provenance.ReviewedAt.IsZero() || strings.TrimSpace(document.Provenance.Evidence) == "") {
		return nil, fmt.Errorf("built-in dependency reputation evidence requires provenance")
	}
	provider := &Provider{records: map[string]skil.PackageReputation{}}
	for _, record := range document.Packages {
		if strings.TrimSpace(record.Ecosystem) == "" || strings.TrimSpace(record.Name) == "" {
			return nil, fmt.Errorf("dependency reputation evidence contains an empty ecosystem or package")
		}
		key := reputationKey(record.Ecosystem, record.Name)
		if _, exists := provider.records[key]; exists {
			return nil, fmt.Errorf("duplicate dependency reputation record for %s/%s", record.Ecosystem, record.Name)
		}
		provider.records[key] = skil.PackageReputation{
			Abandoned: record.Abandoned, LastUpdate: record.LastUpdate,
		}
	}
	return provider, nil
}

func (*Provider) ID() string                 { return "trusted-offline-reputation" }
func (*Provider) VulnerabilityEnabled() bool { return false }

func (*Provider) Query(context.Context, string, string, string) ([]skil.Vulnerability, error) {
	return nil, nil
}

func (p *Provider) Reputation(_ context.Context, ecosystem, name string) (skil.PackageReputation, error) {
	return p.records[reputationKey(ecosystem, name)], nil
}

func reputationKey(ecosystem, name string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "\x00" + strings.ToLower(strings.TrimSpace(name))
}
