package sbom

import (
	"os"
	"testing"
)

func TestCreateGoBinaryUsesEmbeddedModulesAndExactDigest(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	document, err := CreateGoBinary(executable)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Packages) < 1 || len(document.Packages[0].Checksums) != 1 {
		t.Fatalf("binary SBOM is incomplete: %#v", document)
	}
	digest, err := binaryDigest(executable)
	if err != nil {
		t.Fatal(err)
	}
	if document.Packages[0].Checksums[0].ChecksumValue != digest {
		t.Fatal("binary SBOM is not bound to the executable digest")
	}
	for _, pkg := range document.Packages {
		if pkg.Name == "golang.org/x/text" && pkg.VersionInfo == "0.3.6" {
			t.Fatal("binary SBOM included an unrelated source fixture dependency")
		}
	}
}
