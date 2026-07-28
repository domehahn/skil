package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type Dependency struct{ provider skil.VulnerabilityProvider }

var (
	pipDep          = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*(?:==\s*([A-Za-z0-9_.+-]+))?`)
	popularPackages = map[string][]string{
		"PyPI": {"requests", "urllib3", "numpy", "pandas", "django", "flask", "boto3", "cryptography", "pydantic", "pytest", "setuptools", "python-dateutil", "colorama", "jellyfish"},
		"npm":  {"react", "express", "lodash", "axios", "typescript", "webpack", "next", "vue", "angular", "cross-env", "eslint", "prettier"},
		"Go":   {"github.com/gin-gonic/gin", "github.com/spf13/cobra", "github.com/stretchr/testify", "golang.org/x/text", "gopkg.in/yaml.v3"},
	}
)

func NewDependency(provider skil.VulnerabilityProvider) *Dependency {
	return &Dependency{provider: provider}
}
func (d *Dependency) Metadata() skil.AnalyzerMetadata {
	types := []string{"dependency"}
	if d.provider != nil {
		types = append(types, "vulnerability")
	}
	return skil.AnalyzerMetadata{ID: "builtin.dependency", Version: "1.0.0",
		Categories: []string{"dependency-security", "supply-chain"}, AnalysisTypes: types,
		SupportedTypes: []string{"requirements.txt", "package.json", "go.mod"}}
}
func (d *Dependency) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		base := strings.ToLower(file.Path)
		switch {
		case strings.HasSuffix(base, "requirements.txt"):
			scanner := bufio.NewScanner(strings.NewReader(string(file.Data)))
			line := 0
			for scanner.Scan() {
				line++
				text := strings.TrimSpace(scanner.Text())
				if text == "" || strings.HasPrefix(text, "#") {
					continue
				}
				match := pipDep.FindStringSubmatch(text)
				if len(match) < 2 {
					continue
				}
				findings, err := d.inspect(ctx, file, line, "PyPI", match[1], value(match, 2), text)
				if err != nil {
					return nil, err
				}
				out = append(out, findings...)
			}
		case strings.HasSuffix(base, "package.json"):
			var manifest struct {
				Dependencies         map[string]string `json:"dependencies"`
				DevDependencies      map[string]string `json:"devDependencies"`
				OptionalDependencies map[string]string `json:"optionalDependencies"`
				PeerDependencies     map[string]string `json:"peerDependencies"`
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
			for _, name := range names {
				line, text := dependencyLine(file.Data, name)
				findings, err := d.inspect(ctx, file, line, "npm", name, dependencies[name], text)
				if err != nil {
					return nil, err
				}
				out = append(out, findings...)
			}
		case strings.HasSuffix(base, "go.mod"):
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
					findings, err := d.inspect(ctx, file, line+1, "Go", name, version, text)
					if err != nil {
						return nil, err
					}
					out = append(out, findings...)
				}
			}
		}
	}
	return out, nil
}

func dependencyLine(data []byte, name string) (int, string) {
	needle := `"` + name + `"`
	for index, line := range lines(data) {
		if strings.Contains(line, needle) {
			return index + 1, line
		}
	}
	return 1, name
}

func (d *Dependency) inspect(ctx context.Context, file skil.File, line int, ecosystem, name, version, text string) ([]skil.Finding, error) {
	var out []skil.Finding
	unpinned := version == "" || strings.ContainsAny(version, "^*~><") || strings.EqualFold(version, "latest")
	if unpinned {
		rule := RulePattern{Rule: skil.Rule{ID: "SKIL-DEP-001", Title: "Unpinned dependency",
			Category: "dependency-security", Severity: skil.SeverityMedium,
			Description: "Dependency " + name + " is not pinned to an exact version.", Analysis: "dependency",
			Remediation: "Pin the dependency and verify its integrity."}, Confidence: .96}
		out = append(out, makeFinding(rule, file, line, text))
	}
	if target, distance := typosquatTarget(ecosystem, name); target != "" {
		rule := RulePattern{Rule: skil.Rule{ID: "SKIL-DEP-002", Title: "Suspicious dependency name",
			Category: "supply-chain", Severity: skil.SeverityHigh,
			Description: fmt.Sprintf("Dependency %s is edit-distance %d from popular package %s.", name, distance, target), Analysis: "dependency",
			Remediation: "Verify the package identity and publisher."}, Confidence: .8}
		out = append(out, makeFinding(rule, file, line, text))
	}
	if reputationProvider, ok := d.provider.(skil.PackageReputationProvider); ok {
		reputation, err := reputationProvider.Reputation(ctx, ecosystem, name)
		if err != nil {
			return nil, fmt.Errorf("%s reputation lookup for %s: %w", d.provider.ID(), name, err)
		}
		if reputation.Abandoned {
			rule := RulePattern{Rule: skil.Rule{ID: "SKIL-DEP-ABANDONED", Title: "Abandoned dependency",
				Category: "supply-chain", Severity: skil.SeverityMedium,
				Description: "Package reputation metadata marks the dependency as abandoned.", Analysis: "dependency",
				Remediation: "Replace the package with an actively maintained alternative."}, Confidence: .9}
			out = append(out, makeFinding(rule, file, line, text))
		}
	}
	if d.provider != nil && version != "" && !unpinned {
		vulns, err := d.provider.Query(ctx, ecosystem, name, strings.TrimLeft(version, "v="))
		if err != nil {
			return nil, fmt.Errorf("%s lookup for %s@%s: %w", d.provider.ID(), name, version, err)
		}
		for _, vuln := range vulns {
			rule := RulePattern{Rule: skil.Rule{ID: "SKIL-DEP-VULN", Title: "Known vulnerable dependency",
				Category: "dependency-security", Severity: vuln.Severity,
				Description: fmt.Sprintf("%s %s: %s", vuln.ID, name, vuln.Summary), Analysis: "dependency",
				Remediation: "Upgrade to a patched version."}, Confidence: .99}
			f := makeFinding(rule, file, line, text)
			f.References = []string{vuln.ID}
			out = append(out, f)
		}
	}
	return out, nil
}

func typosquatTarget(ecosystem, candidate string) (string, int) {
	normalized := normalizePackageName(candidate)
	for _, popular := range popularPackages[ecosystem] {
		target := normalizePackageName(popular)
		if normalized == target {
			continue
		}
		distance := levenshtein(normalized, target)
		if distance <= 2 && len(normalized) >= 6 {
			return popular, distance
		}
	}
	return "", 0
}

func normalizePackageName(value string) string {
	replacer := strings.NewReplacer("-", "", "_", "", ".", "")
	return replacer.Replace(strings.ToLower(value))
}

func levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	row := make([]int, len(br)+1)
	for index := range row {
		row[index] = index
	}
	for i, left := range ar {
		previous := row[0]
		row[0] = i + 1
		for j, right := range br {
			old := row[j+1]
			cost := 1
			if left == right {
				cost = 0
			}
			row[j+1] = min(row[j+1]+1, row[j]+1, previous+cost)
			previous = old
		}
	}
	return row[len(br)]
}

func value(items []string, index int) string {
	if len(items) > index {
		return items[index]
	}
	return ""
}
