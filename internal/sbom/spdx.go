// Package sbom creates deterministic, network-free software bills of
// materials from the same dependency inventory used by security analysis.
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/pkg/skil"
)

type Document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      CreationInfo   `json:"creationInfo"`
	Packages          []Package      `json:"packages"`
	Relationships     []Relationship `json:"relationships"`
}

type CreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type Package struct {
	Name             string        `json:"name"`
	SPDXID           string        `json:"SPDXID"`
	VersionInfo      string        `json:"versionInfo,omitempty"`
	DownloadLocation string        `json:"downloadLocation"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	Checksums        []Checksum    `json:"checksums,omitempty"`
	ExternalRefs     []ExternalRef `json:"externalRefs,omitempty"`
}

type Checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type ExternalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type Relationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

func Create(artifact skil.Artifact) (Document, error) {
	dependencies, err := analyzer.DiscoverDependencies(artifact)
	if err != nil {
		return Document{}, err
	}
	digest := artifact.SubjectDigest()
	if digest == "" {
		return Document{}, fmt.Errorf("artifact digest is required for SBOM generation")
	}
	rootID := "SPDXRef-Skill"
	root := Package{
		Name: artifact.Name, SPDXID: rootID, VersionInfo: artifact.Version,
		DownloadLocation: "NOASSERTION", FilesAnalyzed: true,
		Checksums: []Checksum{{Algorithm: "SHA256", ChecksumValue: digest}},
	}
	document := Document{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name:              artifact.Name + "-sbom",
		DocumentNamespace: "https://github.com/domehahn/skil/sbom/" + digest,
		CreationInfo: CreationInfo{
			Created:  time.Unix(0, 0).UTC().Format(time.RFC3339),
			Creators: []string{"Tool: skil-" + skil.Version},
		},
		Packages: []Package{root},
		Relationships: []Relationship{{
			Element: "SPDXRef-DOCUMENT", Type: "DESCRIBES", Related: rootID,
		}},
	}
	seen := map[string]bool{}
	for _, item := range dependencies {
		key := strings.Join([]string{item.Ecosystem, item.Name, item.Version}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		idSum := sha256.Sum256([]byte(key))
		id := "SPDXRef-Dependency-" + hex.EncodeToString(idSum[:8])
		pkg := Package{
			Name: item.Name, SPDXID: id, VersionInfo: normalizeVersion(item.Version),
			DownloadLocation: "NOASSERTION", FilesAnalyzed: false,
		}
		if locator := purl(item); locator != "" {
			pkg.ExternalRefs = []ExternalRef{{
				Category: "PACKAGE-MANAGER", Type: "purl", Locator: locator,
			}}
		}
		document.Packages = append(document.Packages, pkg)
		document.Relationships = append(document.Relationships, Relationship{
			Element: rootID, Type: "DEPENDS_ON", Related: id,
		})
	}
	return document, nil
}

func purl(item analyzer.DependencyRecord) string {
	types := map[string]string{
		"PyPI": "pypi", "npm": "npm", "Go": "golang", "crates.io": "cargo",
		"RubyGems": "gem", "Maven": "maven",
	}
	purlType := types[item.Ecosystem]
	if purlType == "" {
		return ""
	}
	name := strings.TrimSpace(item.Name)
	if name == "" {
		return ""
	}
	if item.Ecosystem == "Maven" {
		name = strings.Replace(name, ":", "/", 1)
	}
	path := strings.ReplaceAll(url.PathEscape(name), "%2F", "/")
	locator := "pkg:" + purlType + "/" + path
	if version := normalizeVersion(item.Version); version != "" {
		locator += "@" + url.PathEscape(version)
	}
	return locator
}

func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "=")
	return strings.TrimPrefix(version, "v")
}
