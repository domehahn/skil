package sbom

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestCreateCycloneDXGeneratesValidBOM(t *testing.T) {
	artifact := skil.Artifact{
		Name:    "my-test-skill",
		Version: "1.0.0",
		Digest:  "1234567890abcdef1234567890abcdef",
		Source:  "/path/to/skill",
		Files: []skil.File{
			{Path: "SKILL.md", Data: []byte("# My Test Skill\n")},
		},
	}

	scanResult := &skil.ScanResult{
		Artifact: artifact,
		Observations: []skil.CapabilityObservation{
			{Capability: "permission.filesystem.write", Value: "/tmp/out"},
		},
	}

	bom, err := CreateCycloneDX(artifact, scanResult)
	if err != nil {
		t.Fatalf("CreateCycloneDX failed: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" {
		t.Fatalf("unexpected BOM format/spec: %s / %s", bom.BOMFormat, bom.SpecVersion)
	}

	if len(bom.Components) == 0 {
		t.Fatalf("expected at least 1 root component")
	}

	root := bom.Components[0]
	if root.Name != "my-test-skill" {
		t.Fatalf("unexpected root component name: %s", root.Name)
	}

	foundCapabilityProp := false
	for _, prop := range root.Properties {
		if prop.Name == "skil:capability:permission.filesystem.write" && prop.Value == "/tmp/out" {
			foundCapabilityProp = true
			break
		}
	}

	if !foundCapabilityProp {
		t.Fatalf("expected capability property in CycloneDX output")
	}
}
