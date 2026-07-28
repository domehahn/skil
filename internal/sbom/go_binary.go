package sbom

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

var ErrNotGoBinary = errors.New("input is not a Go binary")

// CreateGoBinary creates an SPDX document from embedded Go build information
// and binds it to the exact executable bytes.
func CreateGoBinary(path string) (Document, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("%w: %v", ErrNotGoBinary, err)
	}
	digest, err := binaryDigest(path)
	if err != nil {
		return Document{}, err
	}
	name := filepath.Base(path)
	rootID := "SPDXRef-Binary"
	document := Document{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name:              name + "-sbom",
		DocumentNamespace: "https://github.com/domehahn/skil/sbom/binary/" + digest,
		CreationInfo: CreationInfo{
			Created:  time.Unix(0, 0).UTC().Format(time.RFC3339),
			Creators: []string{"Tool: skil-" + skil.Version},
		},
		Packages: []Package{{
			Name: name, SPDXID: rootID, VersionInfo: normalizeVersion(info.Main.Version),
			DownloadLocation: "NOASSERTION", FilesAnalyzed: false,
			Checksums:    []Checksum{{Algorithm: "SHA256", ChecksumValue: digest}},
			ExternalRefs: goPURL(info.Main.Path, info.Main.Version),
		}},
		Relationships: []Relationship{{
			Element: "SPDXRef-DOCUMENT", Type: "DESCRIBES", Related: rootID,
		}},
	}
	seen := map[string]bool{}
	for _, module := range info.Deps {
		if module == nil {
			continue
		}
		selected := module
		if module.Replace != nil {
			selected = module.Replace
		}
		key := module.Path + "\x00" + selected.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		sum := sha256.Sum256([]byte(key))
		id := "SPDXRef-GoModule-" + hex.EncodeToString(sum[:8])
		document.Packages = append(document.Packages, Package{
			Name: module.Path, SPDXID: id, VersionInfo: normalizeVersion(selected.Version),
			DownloadLocation: "NOASSERTION", FilesAnalyzed: false,
			ExternalRefs: goPURL(module.Path, selected.Version),
		})
		document.Relationships = append(document.Relationships, Relationship{
			Element: rootID, Type: "DEPENDS_ON", Related: id,
		})
	}
	return document, nil
}

func binaryDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func goPURL(path, version string) []ExternalRef {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	locator := "pkg:golang/" + strings.ReplaceAll(url.PathEscape(path), "%2F", "/")
	if normalized := normalizeVersion(version); normalized != "" && normalized != "(devel)" {
		locator += "@" + url.PathEscape(normalized)
	}
	return []ExternalRef{{Category: "PACKAGE-MANAGER", Type: "purl", Locator: locator}}
}
