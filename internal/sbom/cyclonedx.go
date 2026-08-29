package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/pkg/skil"
)

type CycloneDXBOM struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber"`
	Version      int                  `json:"version"`
	Metadata     CycloneDXMetadata    `json:"metadata"`
	Components   []CycloneDXComponent `json:"components"`
}

type CycloneDXMetadata struct {
	Timestamp string             `json:"timestamp"`
	Tools     []CycloneDXTool    `json:"tools"`
	Component CycloneDXComponent `json:"component"`
}

type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CycloneDXComponent struct {
	Type        string              `json:"type"` // application, library, framework
	BOMRef      string              `json:"bom-ref"`
	Name        string              `json:"name"`
	Version     string              `json:"version,omitempty"`
	Description string              `json:"description,omitempty"`
	Hashes      []CycloneDXHash     `json:"hashes,omitempty"`
	Properties  []CycloneDXProperty `json:"properties,omitempty"`
}

type CycloneDXHash struct {
	Algorithm string `json:"alg"`
	Value     string `json:"content"`
}

type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func CreateCycloneDX(artifact skil.Artifact, result *skil.ScanResult) (CycloneDXBOM, error) {
	digest := artifact.SubjectDigest()
	if digest == "" {
		return CycloneDXBOM{}, fmt.Errorf("artifact digest is required for CycloneDX generation")
	}

	rootRef := "pkg:skil/" + artifact.Name + "@" + artifact.Version
	rootComponent := CycloneDXComponent{
		Type:    "application",
		BOMRef:  rootRef,
		Name:    artifact.Name,
		Version: artifact.Version,
		Hashes:  []CycloneDXHash{{Algorithm: "SHA-256", Value: digest}},
		Properties: []CycloneDXProperty{
			{Name: "skil:artifact:source", Value: artifact.Source},
			{Name: "skil:artifact:file_count", Value: fmt.Sprintf("%d", len(artifact.Files))},
		},
	}

	bom := CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + hex.EncodeToString([]byte(digest[:16])),
		Version:      1,
		Metadata: CycloneDXMetadata{
			Timestamp: time.Unix(0, 0).UTC().Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{Vendor: "SKIL", Name: "skil", Version: skil.Version},
			},
			Component: rootComponent,
		},
		Components: []CycloneDXComponent{rootComponent},
	}

	// Add dependencies
	dependencies, err := analyzer.DiscoverDependencies(artifact)
	if err == nil {
		seen := map[string]bool{}
		for _, dep := range dependencies {
			key := dep.Ecosystem + ":" + dep.Name + ":" + dep.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			idSum := sha256.Sum256([]byte(key))
			depRef := "pkg:" + strings.ToLower(dep.Ecosystem) + "/" + dep.Name + "@" + dep.Version
			bom.Components = append(bom.Components, CycloneDXComponent{
				Type:    "library",
				BOMRef:  depRef,
				Name:    dep.Name,
				Version: dep.Version,
				Hashes:  []CycloneDXHash{{Algorithm: "SHA-256", Value: hex.EncodeToString(idSum[:8])}},
				Properties: []CycloneDXProperty{
					{Name: "skil:ecosystem", Value: dep.Ecosystem},
					{Name: "skil:source_file", Value: dep.File},
				},
			})
		}
	}

	// Add observed capabilities from ScanResult if provided
	if result != nil {
		for _, obs := range result.Observations {
			bom.Components[0].Properties = append(bom.Components[0].Properties, CycloneDXProperty{
				Name:  "skil:capability:" + obs.Capability,
				Value: obs.Value,
			})
		}
	}

	return bom, nil
}
