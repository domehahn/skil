package asps

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed asps-registry.json
var registryFS embed.FS

// Domain and Property are the exported, importable shape of the ASPS
// registry — asps_conformance_test.go keeps its own private structs for
// schema/structural validation of the registry file itself; these are for
// consumers (like the conformance reporter) that just want to query it.
type Domain struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Property struct {
	ID           string   `json:"id"`
	DomainID     string   `json:"domain_id"`
	Domain       string   `json:"domain"`
	Name         string   `json:"name"`
	SKILControls []string `json:"skil_controls"`
	SKILStatus   string   `json:"skil_status"`
}

type Registry struct {
	SchemaVersion string     `json:"schema_version"`
	Snapshot      string     `json:"snapshot"`
	Domains       []Domain   `json:"domains"`
	Properties    []Property `json:"properties"`
}

// Load returns the embedded ASPS registry, parsed from the copy of
// asps-registry.json built into the binary — so callers do not depend on
// the compat/asps source directory being present at runtime.
func Load() (Registry, error) {
	data, err := registryFS.ReadFile("asps-registry.json")
	if err != nil {
		return Registry{}, fmt.Errorf("load embedded ASPS registry: %w", err)
	}
	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return Registry{}, fmt.Errorf("parse embedded ASPS registry: %w", err)
	}
	return reg, nil
}
