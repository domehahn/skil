package packagecheck

import (
	"bufio"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

var (
	semanticVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	checksumLine    = regexp.MustCompile(`^([a-f0-9]{64})[ \t]+(?:\*|  )?(.+)$`)
)

type Result struct {
	Version string   `json:"version" yaml:"version"`
	Errors  []string `json:"errors" yaml:"errors"`
}

func Validate(artifact skil.Artifact, contract skil.SkillContract) Result {
	result := Result{Errors: []string{}}
	files := index(artifact.Files)
	for _, required := range []string{"SKILL.md", "VERSION", "CHANGELOG.md", "checksums.txt"} {
		if _, ok := files[strings.ToLower(required)]; !ok {
			result.Errors = append(result.Errors, "missing required package file "+required)
		}
	}
	versionFile, ok := files["version"]
	if ok {
		result.Version = strings.TrimSpace(string(versionFile.Data))
		if !semanticVersion.MatchString(result.Version) {
			result.Errors = append(result.Errors, "VERSION must contain one semantic version")
		}
		if contract.Skill.Version == "" {
			result.Errors = append(result.Errors, "skill.version is required and must match VERSION")
		} else if result.Version != contract.Skill.Version {
			result.Errors = append(result.Errors, fmt.Sprintf("VERSION %q does not match skill.version %q", result.Version, contract.Skill.Version))
		}
	}
	if changelog, ok := files["changelog.md"]; ok && strings.TrimSpace(string(changelog.Data)) == "" {
		result.Errors = append(result.Errors, "CHANGELOG.md must not be empty")
	}
	if manifest, ok := files["checksums.txt"]; ok {
		result.Errors = append(result.Errors, verifyChecksums(manifest.Data, artifact.Files)...)
	}
	sort.Strings(result.Errors)
	return result
}

// ValidateAuthoring checks a source skill without requiring release-only
// checksums. Package builds continue to use Validate and therefore remain
// fail-closed.
func ValidateAuthoring(artifact skil.Artifact, contract skil.SkillContract) Result {
	result := Result{Errors: []string{}}
	files := index(artifact.Files)
	entrypoint := contract.Entrypoint
	if entrypoint == "" {
		entrypoint = "SKILL.md"
	}
	if _, ok := files[strings.ToLower(entrypoint)]; !ok {
		result.Errors = append(result.Errors, "missing entrypoint "+entrypoint)
	}
	if versionFile, ok := files["version"]; ok {
		result.Version = strings.TrimSpace(string(versionFile.Data))
		if !semanticVersion.MatchString(result.Version) {
			result.Errors = append(result.Errors, "VERSION must contain one semantic version")
		}
		if contract.Skill.Version == "" {
			result.Errors = append(result.Errors, "skill.version is required and must match VERSION")
		} else if result.Version != contract.Skill.Version {
			result.Errors = append(result.Errors, fmt.Sprintf("VERSION %q does not match skill.version %q", result.Version, contract.Skill.Version))
		}
	}
	if changelog, ok := files["changelog.md"]; ok && strings.TrimSpace(string(changelog.Data)) == "" {
		result.Errors = append(result.Errors, "CHANGELOG.md must not be empty")
	}
	sort.Strings(result.Errors)
	return result
}

func index(files []skil.File) map[string]skil.File {
	out := make(map[string]skil.File, len(files))
	for _, file := range files {
		out[strings.ToLower(file.Path)] = file
	}
	return out
}

func verifyChecksums(data []byte, files []skil.File) []string {
	expected := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		match := checksumLine.FindStringSubmatch(line)
		if match == nil {
			return []string{"checksums.txt contains an invalid line"}
		}
		path := strings.TrimPrefix(strings.ReplaceAll(match[2], "\\", "/"), "./")
		if path == "checksums.txt" {
			return []string{"checksums.txt must not contain a self-referential checksum"}
		}
		if _, exists := expected[path]; exists {
			return []string{"checksums.txt contains duplicate path " + path}
		}
		expected[path] = match[1]
	}
	if err := scanner.Err(); err != nil {
		return []string{"read checksums.txt: " + err.Error()}
	}
	var problems []string
	for _, file := range files {
		if file.Path == "checksums.txt" {
			continue
		}
		digest, ok := expected[file.Path]
		if !ok {
			problems = append(problems, "checksums.txt is missing "+file.Path)
			continue
		}
		if digest != file.SHA256 {
			problems = append(problems, "checksum mismatch for "+file.Path)
		}
		delete(expected, file.Path)
	}
	for path := range expected {
		problems = append(problems, "checksums.txt references missing file "+path)
	}
	sort.Strings(problems)
	return problems
}

func Error(result Result) error {
	if len(result.Errors) == 0 {
		return nil
	}
	return errors.New(strings.Join(result.Errors, "; "))
}
