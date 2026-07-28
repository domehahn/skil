package sbom

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestCreateSPDXIsDeterministicAndDeduplicatesDependencies(t *testing.T) {
	data := []byte(`{"dependencies":{"axios":"1.7.2"}}`)
	artifact := skil.Artifact{Name: "demo", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Files: []skil.File{
			{Path: "package.json", Data: data},
			{Path: "package-lock.json", Data: []byte(`{"packages":{"node_modules/axios":{"version":"1.7.2"}}}`)},
		}}
	first, err := Create(artifact)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Create(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("SBOM generation must be deterministic")
	}
	if len(first.Packages) != 2 || len(first.Relationships) != 2 {
		t.Fatalf("unexpected SPDX inventory: %#v", first)
	}
	if first.Packages[1].ExternalRefs[0].Locator != "pkg:npm/axios@1.7.2" {
		t.Fatalf("unexpected purl: %#v", first.Packages[1].ExternalRefs)
	}
	if _, err := json.Marshal(first); err != nil {
		t.Fatal(err)
	}
}

func TestCreateSPDXRequiresDigest(t *testing.T) {
	if _, err := Create(skil.Artifact{Name: "missing"}); err == nil {
		t.Fatal("missing artifact identity must fail")
	}
}
