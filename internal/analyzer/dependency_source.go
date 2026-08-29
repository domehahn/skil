package analyzer

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
	"github.com/pelletier/go-toml/v2"
)

const (
	RuleDependencySourceOverride = "SKIL-DEP-SOURCE-OVERRIDE"
	RuleDependencySourceInsecure = "SKIL-DEP-SOURCE-INSECURE"
	RuleDependencySourceRedirect = "SKIL-DEP-SOURCE-REDIRECT"
)

type DependencySourceAnalyzer struct{}

type dependencySourceObservation struct {
	Ecosystem  string
	Package    string
	URL        string
	SourceKind string
	ConfigKey  string
	Location   skil.Location
}

func NewDependencySource() *DependencySourceAnalyzer { return &DependencySourceAnalyzer{} }

func (a *DependencySourceAnalyzer) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.dependency-source", Version: "2.0.0",
		Domain: "dependency-trust", Subdomain: "registry-redirection",
		Categories:     []string{"dependency-trust", "supply-chain"},
		AnalysisTypes:  []string{"dependency-trust"},
		SupportedTypes: []string{"npmrc", "conf", "toml", "xml", "sh"},
	}
}

func (a *DependencySourceAnalyzer) Rules() []skil.Rule {
	return []skil.Rule{
		{ID: RuleDependencySourceOverride, Title: "Unknown package registry configured", Category: "dependency-trust", Severity: skil.SeverityMedium, Analysis: "dependency-trust", AppliesTo: []string{"npmrc", "conf", "toml", "xml", "sh"}, Description: "A package manager is configured to use a non-official registry whose trust must be decided by policy.", Remediation: "Add the canonical registry URL to dependency_sources.<ecosystem>.allowed only after review."},
		{ID: RuleDependencySourceInsecure, Title: "Insecure package registry configured", Category: "dependency-trust", Severity: skil.SeverityHigh, Analysis: "dependency-trust", AppliesTo: []string{"npmrc", "conf", "toml", "xml", "sh"}, Description: "A package manager registry uses an insecure or ambiguous URL.", Remediation: "Use a canonical HTTPS registry URL without credentials, query strings, or fragments."},
		{ID: RuleDependencySourceRedirect, Title: "Package source replacement configured", Category: "dependency-trust", Severity: skil.SeverityHigh, Analysis: "dependency-trust", AppliesTo: []string{"toml"}, Description: "Cargo source replacement redirects dependency resolution away from the declared source.", Remediation: "Remove source replacement or pin the reviewed replacement registry in policy and attestation."},
	}
}

func (a *DependencySourceAnalyzer) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	findings, _, err := a.AnalyzeCapabilities(ctx, ac)
	return findings, err
}

func (a *DependencySourceAnalyzer) AnalyzeCapabilities(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, []skil.CapabilityObservation, error) {
	var findings []skil.Finding
	var capabilities []skil.CapabilityObservation
	for _, file := range ac.Artifact.Files {
		observed, err := parseDependencySources(file)
		if err != nil {
			return nil, nil, fmt.Errorf("parse dependency source config %s: %w", file.Path, err)
		}
		for _, source := range observed {
			canonical, err := NormalizeRegistryURL(source.URL)
			evidence := map[string]any{
				"ecosystem": source.Ecosystem, "package": source.Package,
				"source_url": source.URL, "source_kind": source.SourceKind, "config_key": source.ConfigKey,
			}
			if err != nil {
				findings = append(findings, dependencySourceFinding(ac.Artifact, file, source, a.ruleByID(RuleDependencySourceInsecure), err.Error()))
				continue
			}
			evidence["canonical_url"] = canonical
			capabilities = append(capabilities, skil.CapabilityObservation{
				Capability: "dependency.source", Value: canonical, Location: source.Location,
				Analyzer: "builtin.dependency-source", Evidence: evidence,
			})
			if source.SourceKind == "replacement" {
				findings = append(findings, dependencySourceFinding(ac.Artifact, file, source, a.ruleByID(RuleDependencySourceRedirect), canonical))
			} else if !IsOfficialRegistry(source.Ecosystem, canonical) {
				findings = append(findings, dependencySourceFinding(ac.Artifact, file, source, a.ruleByID(RuleDependencySourceOverride), canonical))
			}
		}
	}
	sort.Slice(capabilities, func(i, j int) bool {
		return capabilities[i].Location.File+"\x00"+capabilities[i].Value < capabilities[j].Location.File+"\x00"+capabilities[j].Value
	})
	return findings, capabilities, nil
}

func (a *DependencySourceAnalyzer) ruleByID(id string) skil.Rule {
	for _, rule := range a.Rules() {
		if rule.ID == id {
			return rule
		}
	}
	return skil.Rule{ID: id}
}

func dependencySourceFinding(artifact skil.Artifact, file skil.File, source dependencySourceObservation, rule skil.Rule, detail string) skil.Finding {
	finding := makeFinding(RulePattern{Rule: rule, Confidence: .99}, file, source.Location.StartLine, source.ConfigKey+"="+source.URL)
	finding.Message = rule.Description + " Observed: " + detail
	finding.Evidence = map[string]any{
		"ecosystem": source.Ecosystem, "package": source.Package, "source_url": source.URL,
		"source_kind": source.SourceKind, "config_key": source.ConfigKey,
	}
	finding.Fingerprint = fingerprint(artifact.Name, rule.ID, file.Path, fmt.Sprint(source.Location.StartLine), source.URL)
	return finding
}

func parseDependencySources(file skil.File) ([]dependencySourceObservation, error) {
	clean := strings.ToLower(strings.ReplaceAll(file.Path, "\\", "/"))
	name := path.Base(clean)
	switch {
	case name == ".npmrc":
		return parseKeyValueRegistries(file, "npm", map[string]string{"registry": "registry"})
	case name == "pip.conf" || name == "pip.ini":
		return parseKeyValueRegistries(file, "pypi", map[string]string{"index-url": "index", "extra-index-url": "extra-index"})
	case name == "pyproject.toml":
		return parsePythonTOML(file)
	case strings.HasSuffix(clean, ".cargo/config.toml"):
		return parseCargoTOML(file)
	case name == "pom.xml" || name == "settings.xml":
		return parseMavenXML(file)
	case strings.HasSuffix(name, ".sh"):
		return parseInstallFlags(file), nil
	default:
		return nil, nil
	}
}

func parseKeyValueRegistries(file skil.File, ecosystem string, keys map[string]string) ([]dependencySourceObservation, error) {
	var out []dependencySourceObservation
	scanner := bufio.NewScanner(strings.NewReader(string(file.Data)))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") || strings.HasPrefix(text, "[") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		kind, exact := keys[strings.ToLower(key)]
		pkg := ""
		if ecosystem == "npm" && strings.HasPrefix(key, "@") && strings.HasSuffix(key, ":registry") {
			kind, exact, pkg = "scope-registry", true, strings.TrimSuffix(key, ":registry")
		}
		if exact {
			out = append(out, dependencySourceObservation{Ecosystem: ecosystem, Package: pkg, URL: value, SourceKind: kind, ConfigKey: key, Location: skil.Location{File: file.Path, StartLine: line, EndLine: line}})
		}
	}
	return out, scanner.Err()
}

func parsePythonTOML(file skil.File) ([]dependencySourceObservation, error) {
	var document map[string]any
	if err := toml.Unmarshal(file.Data, &document); err != nil {
		return nil, err
	}
	var out []dependencySourceObservation
	tool, _ := document["tool"].(map[string]any)
	poetry, _ := tool["poetry"].(map[string]any)
	for _, item := range anySlice(poetry["source"]) {
		entry, _ := item.(map[string]any)
		if sourceURL, _ := entry["url"].(string); sourceURL != "" {
			name, _ := entry["name"].(string)
			out = append(out, sourceAt(file, "pypi", name, sourceURL, "poetry-source", "tool.poetry.source"))
		}
	}
	uv, _ := tool["uv"].(map[string]any)
	for _, item := range anySlice(uv["index"]) {
		entry, _ := item.(map[string]any)
		if sourceURL, _ := entry["url"].(string); sourceURL != "" {
			name, _ := entry["name"].(string)
			out = append(out, sourceAt(file, "pypi", name, sourceURL, "uv-index", "tool.uv.index"))
		}
	}
	return out, nil
}

func parseCargoTOML(file skil.File) ([]dependencySourceObservation, error) {
	var document map[string]any
	if err := toml.Unmarshal(file.Data, &document); err != nil {
		return nil, err
	}
	var out []dependencySourceObservation
	sources, _ := document["source"].(map[string]any)
	for name, raw := range sources {
		entry, _ := raw.(map[string]any)
		if replacement, _ := entry["replace-with"].(string); replacement != "" {
			target, _ := sources[replacement].(map[string]any)
			registry, _ := target["registry"].(string)
			out = append(out, sourceAt(file, "cargo", name, registry, "replacement", "source."+name+".replace-with"))
		} else if registry, _ := entry["registry"].(string); registry != "" {
			out = append(out, sourceAt(file, "cargo", name, registry, "source", "source."+name+".registry"))
		}
	}
	registries, _ := document["registries"].(map[string]any)
	for name, raw := range registries {
		entry, _ := raw.(map[string]any)
		if registry, _ := entry["index"].(string); registry != "" {
			out = append(out, sourceAt(file, "cargo", name, registry, "registry", "registries."+name+".index"))
		}
	}
	return out, nil
}

func parseMavenXML(file skil.File) ([]dependencySourceObservation, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(file.Data)))
	var out []dependencySourceObservation
	stack := []string{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		switch typed := token.(type) {
		case xml.StartElement:
			stack = append(stack, typed.Name.Local)
			if typed.Name.Local == "url" && containsAny(stack, "repository", "pluginRepository", "mirror") {
				var value string
				if err := decoder.DecodeElement(&value, &typed); err != nil {
					return nil, err
				}
				stack = stack[:len(stack)-1]
				value = strings.TrimSpace(value)
				out = append(out, sourceAt(file, "maven", "", value, "repository", strings.Join(stack, ".")+".url"))
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
}

func parseInstallFlags(file skil.File) []dependencySourceObservation {
	var out []dependencySourceObservation
	scanner := bufio.NewScanner(strings.NewReader(string(file.Data)))
	for line := 1; scanner.Scan(); line++ {
		fields := strings.Fields(scanner.Text())
		for index, field := range fields {
			var ecosystem, kind string
			switch field {
			case "--registry":
				ecosystem, kind = "npm", "cli-registry"
			case "--index-url":
				ecosystem, kind = "pypi", "cli-index"
			case "--extra-index-url":
				ecosystem, kind = "pypi", "cli-extra-index"
			}
			if ecosystem != "" && index+1 < len(fields) {
				out = append(out, dependencySourceObservation{Ecosystem: ecosystem, URL: strings.Trim(fields[index+1], "'\""), SourceKind: kind, ConfigKey: field, Location: skil.Location{File: file.Path, StartLine: line, EndLine: line}})
			}
		}
	}
	return out
}

// NormalizeRegistryURL prevents trust-policy bypass through casing, default
// ports, dot segments, credentials, queries, fragments, or trailing slashes.
func NormalizeRegistryURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid registry URL")
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("registry URL must use https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("registry URL must not contain credentials, query, or fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	port := parsed.Port()
	if port == "443" {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	cleanPath := path.Clean("/" + strings.TrimPrefix(parsed.EscapedPath(), "/"))
	return "https://" + host + strings.TrimSuffix(cleanPath, "/") + "/", nil
}

func IsOfficialRegistry(ecosystem, canonical string) bool {
	official := map[string][]string{
		"npm":   {"https://registry.npmjs.org/"},
		"pypi":  {"https://pypi.org/simple/"},
		"cargo": {"https://github.com/rust-lang/crates.io-index/", "https://index.crates.io/"},
		"maven": {"https://repo.maven.apache.org/maven2/"},
	}
	for _, trusted := range official[ecosystem] {
		if canonical == trusted {
			return true
		}
	}
	return false
}

func sourceAt(file skil.File, ecosystem, pkg, sourceURL, kind, key string) dependencySourceObservation {
	line := lineOfText(file.Data, sourceURL)
	return dependencySourceObservation{Ecosystem: ecosystem, Package: pkg, URL: sourceURL, SourceKind: kind, ConfigKey: key, Location: skil.Location{File: file.Path, StartLine: line, EndLine: line}}
}

func anySlice(value any) []any {
	items, _ := value.([]any)
	return items
}

func lineOfText(data []byte, value string) int {
	line, _ := lineContaining(data, value)
	if line == 0 {
		return 1
	}
	return line
}

func containsAny(stack []string, values ...string) bool {
	for _, item := range stack {
		for _, value := range values {
			if item == value {
				return true
			}
		}
	}
	return false
}
