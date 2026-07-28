package analyzer

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type DependencyRecord struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Raw       string `json:"-"`
}

var (
	pipDep       = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*(?:==\s*([A-Za-z0-9_.+-]+))?`)
	tomlName     = regexp.MustCompile(`^\s*name\s*=\s*"([^"]+)"`)
	tomlVersion  = regexp.MustCompile(`^\s*version\s*=\s*"([^"]+)"`)
	cargoDep     = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")`)
	gemLockDep   = regexp.MustCompile(`^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)`)
	pyProjectDep = regexp.MustCompile(`["']([A-Za-z0-9_.-]+)\s*(?:==\s*([A-Za-z0-9_.+-]+))?["']`)
)

// DiscoverDependencies returns a deterministic, network-free inventory from
// supported manifests and lockfiles. It does not claim dependency resolution.
func DiscoverDependencies(artifact skil.Artifact) ([]DependencyRecord, error) {
	var out []DependencyRecord
	for _, file := range artifact.Files {
		base := strings.ToLower(file.Path)
		var records []DependencyRecord
		var err error
		switch {
		case strings.HasSuffix(base, "requirements.txt"):
			records = parseRequirements(file)
		case strings.HasSuffix(base, "package.json"):
			records, err = parsePackageJSON(file)
		case strings.HasSuffix(base, "package-lock.json"):
			records, err = parsePackageLock(file)
		case strings.HasSuffix(base, "go.mod"):
			records = parseGoMod(file)
		case strings.HasSuffix(base, "pyproject.toml"):
			records = parsePyProject(file)
		case strings.HasSuffix(base, "poetry.lock"), strings.HasSuffix(base, "uv.lock"):
			records = parseTOMLLock(file, "PyPI")
		case strings.HasSuffix(base, "cargo.lock"):
			records = parseTOMLLock(file, "crates.io")
		case strings.HasSuffix(base, "cargo.toml"):
			records = parseCargoManifest(file)
		case strings.HasSuffix(base, "gemfile.lock"):
			records = parseGemLock(file)
		case strings.HasSuffix(base, "pom.xml"):
			records, err = parsePOM(file)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, records...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, nil
}

func parseRequirements(file skil.File) []DependencyRecord {
	var out []DependencyRecord
	scanner := bufio.NewScanner(strings.NewReader(string(file.Data)))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		match := pipDep.FindStringSubmatch(text)
		if len(match) >= 2 {
			out = append(out, dependency(file, line, "PyPI", match[1], value(match, 2), text))
		}
	}
	return out
}

func parsePackageJSON(file skil.File) ([]DependencyRecord, error) {
	var manifest struct {
		Dependencies, DevDependencies, OptionalDependencies, PeerDependencies map[string]string
	}
	if err := json.Unmarshal(file.Data, &manifest); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file.Path, err)
	}
	dependencies := map[string]string{}
	for _, section := range []map[string]string{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies, manifest.PeerDependencies} {
		for name, version := range section {
			dependencies[name] = version
		}
	}
	names := make([]string, 0, len(dependencies))
	for name := range dependencies {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]DependencyRecord, 0, len(names))
	for _, name := range names {
		line, raw := dependencyLine(file.Data, name)
		out = append(out, dependency(file, line, "npm", name, dependencies[name], raw))
	}
	return out, nil
}

func parsePackageLock(file skil.File) ([]DependencyRecord, error) {
	var lock struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(file.Data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file.Path, err)
	}
	var out []DependencyRecord
	for path, item := range lock.Packages {
		if path == "" || item.Version == "" {
			continue
		}
		name := item.Name
		if name == "" {
			name = strings.TrimPrefix(path, "node_modules/")
			if index := strings.LastIndex(name, "/node_modules/"); index >= 0 {
				name = name[index+len("/node_modules/"):]
			}
		}
		line, raw := dependencyLine(file.Data, name)
		out = append(out, dependency(file, line, "npm", name, item.Version, raw))
	}
	return out, nil
}

func parseGoMod(file skil.File) []DependencyRecord {
	var out []DependencyRecord
	inRequireBlock := false
	for line, text := range lines(file.Data) {
		fields := strings.Fields(strings.SplitN(text, "//", 2)[0])
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "require" && len(fields) == 2 && fields[1] == "(" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && fields[0] == ")" {
			inRequireBlock = false
			continue
		}
		var name, version string
		if inRequireBlock && len(fields) >= 2 {
			name, version = fields[0], fields[1]
		} else if len(fields) >= 3 && fields[0] == "require" {
			name, version = fields[1], fields[2]
		}
		if name != "" {
			out = append(out, dependency(file, line+1, "Go", name, version, text))
		}
	}
	return out
}

func parsePyProject(file skil.File) []DependencyRecord {
	var out []DependencyRecord
	inPoetry := false
	for line, text := range lines(file.Data) {
		trimmed := strings.TrimSpace(text)
		if strings.HasPrefix(trimmed, "[") {
			inPoetry = trimmed == "[tool.poetry.dependencies]"
		}
		if inPoetry {
			match := cargoDep.FindStringSubmatch(text)
			if len(match) > 1 && !strings.EqualFold(match[1], "python") {
				out = append(out, dependency(file, line+1, "PyPI", match[1], first(match[2], value(match, 3)), text))
			}
			continue
		}
		for _, match := range pyProjectDep.FindAllStringSubmatch(text, -1) {
			out = append(out, dependency(file, line+1, "PyPI", match[1], value(match, 2), text))
		}
	}
	return out
}

func parseTOMLLock(file skil.File, ecosystem string) []DependencyRecord {
	var out []DependencyRecord
	name, version, start := "", "", 0
	flush := func() {
		if name != "" {
			out = append(out, dependency(file, start, ecosystem, name, version, name+"=="+version))
		}
		name, version, start = "", "", 0
	}
	for line, text := range lines(file.Data) {
		if strings.TrimSpace(text) == "[[package]]" {
			flush()
			start = line + 1
			continue
		}
		if match := tomlName.FindStringSubmatch(text); len(match) == 2 {
			name = match[1]
		}
		if match := tomlVersion.FindStringSubmatch(text); len(match) == 2 {
			version = match[1]
		}
	}
	flush()
	return out
}

func parseCargoManifest(file skil.File) []DependencyRecord {
	var out []DependencyRecord
	inDependencies := false
	for line, text := range lines(file.Data) {
		trimmed := strings.TrimSpace(text)
		if strings.HasPrefix(trimmed, "[") {
			inDependencies = strings.HasSuffix(strings.Trim(trimmed, "[]"), "dependencies")
			continue
		}
		if !inDependencies {
			continue
		}
		if match := cargoDep.FindStringSubmatch(text); len(match) > 1 {
			out = append(out, dependency(file, line+1, "crates.io", match[1], first(match[2], value(match, 3)), text))
		}
	}
	return out
}

func parseGemLock(file skil.File) []DependencyRecord {
	var out []DependencyRecord
	for line, text := range lines(file.Data) {
		if match := gemLockDep.FindStringSubmatch(text); len(match) == 3 {
			out = append(out, dependency(file, line+1, "RubyGems", match[1], match[2], text))
		}
	}
	return out
}

func parsePOM(file skil.File) ([]DependencyRecord, error) {
	var project struct {
		Dependencies []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
		} `xml:"dependencies>dependency"`
	}
	if err := xml.Unmarshal(file.Data, &project); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file.Path, err)
	}
	var out []DependencyRecord
	for _, item := range project.Dependencies {
		if item.GroupID == "" || item.ArtifactID == "" {
			continue
		}
		name := item.GroupID + ":" + item.ArtifactID
		line, raw := dependencyLine(file.Data, item.ArtifactID)
		out = append(out, dependency(file, line, "Maven", name, item.Version, raw))
	}
	return out, nil
}

func dependency(file skil.File, line int, ecosystem, name, version, raw string) DependencyRecord {
	return DependencyRecord{Ecosystem: ecosystem, Name: name, Version: version, File: file.Path, Line: line, Raw: raw}
}

func first(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
