package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type Dependency struct{ provider skil.VulnerabilityProvider }

var (
	popularPackages = map[string][]string{
		"PyPI": {"requests", "urllib3", "numpy", "pandas", "django", "flask", "boto3", "cryptography", "pydantic", "pytest", "setuptools", "python-dateutil", "colorama", "jellyfish"},
		"npm":  {"react", "express", "lodash", "axios", "typescript", "webpack", "next", "vue", "angular", "cross-env", "eslint", "prettier"},
		"Go":   {"github.com/gin-gonic/gin", "github.com/spf13/cobra", "github.com/stretchr/testify", "golang.org/x/text", "gopkg.in/yaml.v3"},
	}
)

func NewDependency(provider skil.VulnerabilityProvider) *Dependency {
	return &Dependency{provider: provider}
}
func (d *Dependency) Diagnostics() []skil.Diagnostic {
	if source, ok := d.provider.(interface{ Diagnostics() []skil.Diagnostic }); ok {
		return source.Diagnostics()
	}
	return nil
}
func (d *Dependency) Metadata() skil.AnalyzerMetadata {
	types := []string{"dependency"}
	if vulnerabilityEnabled(d.provider) {
		types = append(types, "vulnerability")
	}
	return skil.AnalyzerMetadata{ID: "builtin.dependency", Version: "1.0.0",
		Categories: []string{"dependency-trust"}, AnalysisTypes: types,
		SupportedTypes: []string{"requirements.txt", "package.json", "package-lock.json", "go.mod",
			"pyproject.toml", "poetry.lock", "uv.lock", "Cargo.toml", "Cargo.lock", "Gemfile.lock", "pom.xml"}}
}
func (d *Dependency) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	records, err := DiscoverDependencies(ac.Artifact)
	if err != nil {
		return nil, err
	}
	files := make(map[string]skil.File, len(ac.Artifact.Files))
	for _, file := range ac.Artifact.Files {
		files[file.Path] = file
	}
	batch, batchEnabled := d.provider.(skil.BatchVulnerabilityProvider)
	batchEnabled = batchEnabled && vulnerabilityEnabled(d.provider)
	var queries []skil.VulnerabilityQuery
	var queryRecords []DependencyRecord
	for _, record := range records {
		findings, err := d.inspect(ctx, files[record.File], record.Line, record.Ecosystem, record.Name, record.Version, record.Raw, !batchEnabled)
		if err != nil {
			return nil, err
		}
		out = append(out, findings...)
		if batchEnabled && record.Version != "" && dependencyIsExact(record.Ecosystem, record.File, record.Version) {
			queries = append(queries, skil.VulnerabilityQuery{
				Ecosystem: record.Ecosystem, Package: record.Name, Version: strings.TrimLeft(record.Version, "v="),
			})
			queryRecords = append(queryRecords, record)
		}
	}
	if len(queries) > 0 {
		results, err := batch.QueryBatch(ctx, queries)
		if err != nil {
			return nil, fmt.Errorf("%s batch lookup: %w", d.provider.ID(), err)
		}
		if len(results) != len(queries) {
			return nil, fmt.Errorf("%s batch lookup returned %d results for %d queries", d.provider.ID(), len(results), len(queries))
		}
		for index, vulnerabilities := range results {
			record := queryRecords[index]
			out = append(out, vulnerabilityFindings(files[record.File], record.Line, record.Raw, record.Name, vulnerabilities)...)
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

func (d *Dependency) inspect(ctx context.Context, file skil.File, line int, ecosystem, name, version, text string, queryVulnerabilities bool) ([]skil.Finding, error) {
	var out []skil.Finding
	unpinned := !dependencyIsExact(ecosystem, file.Path, version)
	if unpinned {
		rule := RulePattern{Rule: skil.Rule{ID: "SKIL-DEP-001", Title: "Unpinned dependency",
			Category: "dependency-trust", Severity: skil.SeverityMedium,
			Description: "Dependency " + name + " is not pinned to an exact version.", Analysis: "dependency",
			Remediation: "Pin the dependency and verify its integrity."}, Confidence: .96}
		out = append(out, makeFinding(rule, file, line, text))
	}
	if target, distance := typosquatTarget(ecosystem, name); target != "" {
		rule := RulePattern{Rule: skil.Rule{ID: "SKIL-DEP-002", Title: "Suspicious dependency name",
			Category: "dependency-trust", Severity: skil.SeverityHigh,
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
				Category: "dependency-trust", Severity: skil.SeverityMedium,
				Description: "Package reputation metadata marks the dependency as abandoned.", Analysis: "dependency",
				Remediation: "Replace the package with an actively maintained alternative."}, Confidence: .9}
			out = append(out, makeFinding(rule, file, line, text))
		}
	}
	if queryVulnerabilities && vulnerabilityEnabled(d.provider) && version != "" && !unpinned {
		vulns, err := d.provider.Query(ctx, ecosystem, name, strings.TrimLeft(version, "v="))
		if err != nil {
			return nil, fmt.Errorf("%s lookup for %s@%s: %w", d.provider.ID(), name, version, err)
		}
		out = append(out, vulnerabilityFindings(file, line, text, name, vulns)...)
	}
	return out, nil
}

func vulnerabilityEnabled(provider skil.VulnerabilityProvider) bool {
	if provider == nil {
		return false
	}
	if configured, ok := provider.(interface{ VulnerabilityEnabled() bool }); ok {
		return configured.VulnerabilityEnabled()
	}
	return true
}

func vulnerabilityFindings(file skil.File, line int, text, name string, vulnerabilities []skil.Vulnerability) []skil.Finding {
	out := make([]skil.Finding, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		rule := RulePattern{Rule: skil.Rule{ID: "SKIL-DEP-VULN", Title: "Known vulnerable dependency",
			Category: "dependency-trust", Severity: vulnerability.Severity,
			Description: fmt.Sprintf("%s %s: %s", vulnerability.ID, name, vulnerability.Summary), Analysis: "dependency",
			Remediation: "Upgrade to a patched version."}, Confidence: .99}
		finding := makeFinding(rule, file, line, text)
		finding.References = vulnerabilityReferences(vulnerability)
		out = append(out, finding)
	}
	return out
}

func vulnerabilityReferences(vulnerability skil.Vulnerability) []string {
	seen := map[string]bool{}
	references := make([]string, 0, len(vulnerability.Aliases)+1)
	for _, reference := range append([]string{vulnerability.ID}, vulnerability.Aliases...) {
		if reference != "" && !seen[reference] {
			seen[reference] = true
			references = append(references, reference)
		}
	}
	sort.Strings(references)
	return references
}

func dependencyIsExact(ecosystem, path, version string) bool {
	if version == "" || strings.ContainsAny(version, "^*~><$[](), ") || strings.EqualFold(version, "latest") {
		return false
	}
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".lock") || strings.HasSuffix(lower, "package-lock.json") {
		return true
	}
	if ecosystem == "crates.io" && strings.HasSuffix(lower, "cargo.toml") {
		return strings.HasPrefix(version, "=")
	}
	return !strings.Contains(version, "${")
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
