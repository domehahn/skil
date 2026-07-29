// Package lint performs fast, deterministic authoring checks without running
// skill code or invoking security-analysis providers.
package lint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/contracts"
	"github.com/domehahn/skil/internal/packagecheck"
	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

type Level string

const (
	LevelError   Level = "error"
	LevelWarning Level = "warning"
	LevelNote    Level = "note"
)

type Profile string

const (
	ProfileDefault  Profile = "default"
	ProfileStrict   Profile = "strict"
	ProfilePortable Profile = "portable"
	ProfilePublish  Profile = "publish"
)

func ParseProfile(value string) (Profile, error) {
	profile := Profile(strings.ToLower(strings.TrimSpace(value)))
	switch profile {
	case ProfileDefault, ProfileStrict, ProfilePortable, ProfilePublish:
		return profile, nil
	default:
		return "", fmt.Errorf("unsupported lint profile %q (expected default, strict, portable, or publish)", value)
	}
}

type Issue struct {
	RuleID      string        `json:"rule_id"`
	Level       Level         `json:"level"`
	Title       string        `json:"title"`
	Message     string        `json:"message"`
	Location    skil.Location `json:"location"`
	Remediation string        `json:"remediation,omitempty"`
	Fingerprint string        `json:"fingerprint"`
}

type Summary struct {
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Notes    int `json:"notes"`
}

type Result struct {
	SchemaVersion string        `json:"schema_version"`
	Artifact      skil.Artifact `json:"artifact"`
	Status        skil.Status   `json:"status"`
	Profile       Profile       `json:"profile"`
	Strict        bool          `json:"strict"`
	Summary       Summary       `json:"summary"`
	Issues        []Issue       `json:"issues"`
	GeneratedAt   time.Time     `json:"generated_at"`
}

var (
	contractNames = map[string]bool{
		"skill.yaml": true, "skill.yml": true, "skil.yaml": true, "skil.yml": true,
		".skil/contract.yaml": true,
	}
	semverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	h1Pattern     = regexp.MustCompile(`(?m)^#\s+\S`)
	placeholder   = regexp.MustCompile(`(?im)\b(?:TODO|TBD|FIXME)\b`)
	localLink     = regexp.MustCompile(`!?\[[^\]]*\]\(([^)\s]+)(?:\s+["'][^"']*["'])?\)`)
)

func Analyze(artifact skil.Artifact, strict bool) Result {
	profile := ProfileDefault
	if strict {
		profile = ProfileStrict
	}
	return AnalyzeProfile(artifact, profile)
}

func AnalyzeProfile(artifact skil.Artifact, profile Profile) Result {
	strict := profile != ProfileDefault
	result := Result{
		SchemaVersion: "1.0.0",
		Artifact:      artifact,
		Profile:       profile,
		Strict:        strict,
		Issues:        []Issue{},
		GeneratedAt:   time.Now().UTC(),
	}
	files := fileIndex(artifact.Files)
	contractPaths := findContractPaths(artifact.Files)
	var contract *skil.SkillContract
	var format contracts.Format
	var contractPath string

	switch len(contractPaths) {
	case 0:
		add(&result, "SKIL-LINT-CONTRACT-MISSING", LevelError, "Missing skill contract",
			"No skill contract was found.", "", 0,
			"Add skill.yaml, skil.yaml, or .skil/contract.yaml.")
	case 1:
		contractPath = contractPaths[0]
		parsed, foundPath, foundFormat, err := contracts.FindWithFormat(artifact)
		if err != nil {
			add(&result, "SKIL-LINT-CONTRACT-INVALID", LevelError, "Invalid skill contract",
				err.Error(), contractPath, 1, "Correct the contract syntax, schema, and semantic consistency.")
		} else {
			contract, contractPath, format = parsed, foundPath, foundFormat
		}
	default:
		add(&result, "SKIL-LINT-CONTRACT-AMBIGUOUS", LevelError, "Ambiguous skill contract",
			"Multiple contract files were found: "+strings.Join(contractPaths, ", "), contractPaths[0], 1,
			"Keep exactly one root skill contract.")
	}

	skillFile, hasSkill := files["skill.md"]
	if !hasSkill {
		add(&result, "SKIL-LINT-SKILL-MISSING", LevelError, "Missing SKILL.md",
			"A concrete skill must contain a root SKILL.md.", "", 0, "Add a root SKILL.md entrypoint.")
	} else {
		lintSkillMarkdown(&result, skillFile, files, contract)
	}

	if contract != nil {
		lintContract(&result, artifact, *contract, contractPath, format, profile)
	}
	lintStructuredFiles(&result, artifact.Files)
	lintDependencyLocks(&result, files)
	lintAdvanced(&result, artifact, contract, profile)

	sort.SliceStable(result.Issues, func(i, j int) bool {
		left, right := result.Issues[i], result.Issues[j]
		if rank(left.Level) != rank(right.Level) {
			return rank(left.Level) < rank(right.Level)
		}
		if left.Location.File != right.Location.File {
			return left.Location.File < right.Location.File
		}
		if left.Location.StartLine != right.Location.StartLine {
			return left.Location.StartLine < right.Location.StartLine
		}
		return left.RuleID < right.RuleID
	})
	for _, issue := range result.Issues {
		switch issue.Level {
		case LevelError:
			result.Summary.Errors++
		case LevelWarning:
			result.Summary.Warnings++
		default:
			result.Summary.Notes++
		}
	}
	switch {
	case result.Summary.Errors > 0 || strict && result.Summary.Warnings > 0:
		result.Status = skil.StatusFail
	case result.Summary.Warnings > 0:
		result.Status = skil.StatusWarn
	default:
		result.Status = skil.StatusPass
	}
	return result
}

func lintSkillMarkdown(result *Result, file skil.File, files map[string]skil.File, contract *skil.SkillContract) {
	text := string(file.Data)
	if strings.TrimSpace(text) == "" {
		add(result, "SKIL-LINT-SKILL-EMPTY", LevelError, "Empty SKILL.md",
			"SKILL.md contains no instructions.", file.Path, 1, "Document the skill purpose, constraints, and workflow.")
		return
	}
	headings := h1Pattern.FindAllStringIndex(text, -1)
	if len(headings) == 0 {
		add(result, "SKIL-LINT-H1-MISSING", LevelWarning, "Missing primary heading",
			"SKILL.md has no level-one heading.", file.Path, 1, "Add one descriptive '# …' heading.")
	} else if len(headings) > 1 {
		add(result, "SKIL-LINT-H1-MULTIPLE", LevelWarning, "Multiple primary headings",
			fmt.Sprintf("SKILL.md contains %d level-one headings.", len(headings)), file.Path,
			lineAt(file.Data, headings[1][0]), "Use one level-one heading and level-two headings for sections.")
	}
	if match := placeholder.FindIndex(file.Data); match != nil {
		add(result, "SKIL-LINT-PLACEHOLDER", LevelWarning, "Unresolved authoring placeholder",
			"SKILL.md contains TODO, TBD, or FIXME text.", file.Path, lineAt(file.Data, match[0]),
			"Resolve the placeholder before publishing the skill.")
	}
	frontmatter, frontmatterPresent, frontmatterErr := parseFrontmatter(file.Data)
	if frontmatterErr != nil {
		add(result, "SKIL-LINT-FRONTMATTER-INVALID", LevelError, "Invalid SKILL.md frontmatter",
			frontmatterErr.Error(), file.Path, 1, "Use a YAML mapping between opening and closing '---' lines.")
	} else if !frontmatterPresent {
		add(result, "SKIL-LINT-FRONTMATTER-MISSING", LevelWarning, "Missing SKILL.md frontmatter",
			"SKILL.md does not declare authoring metadata.", file.Path, 1,
			"Add YAML frontmatter with name and description.")
	} else {
		lintFrontmatter(result, file, frontmatter, contract)
	}
	lintLocalLinks(result, file, files)
}

func lintFrontmatter(result *Result, file skil.File, metadata map[string]any, contract *skil.SkillContract) {
	name, _ := metadata["name"].(string)
	description, _ := metadata["description"].(string)
	if strings.TrimSpace(name) == "" {
		add(result, "SKIL-LINT-FRONTMATTER-NAME", LevelWarning, "Missing frontmatter name",
			"SKILL.md frontmatter has no non-empty name.", file.Path, 2, "Declare the skill name.")
	}
	if strings.TrimSpace(description) == "" {
		add(result, "SKIL-LINT-FRONTMATTER-DESCRIPTION", LevelWarning, "Missing frontmatter description",
			"SKILL.md frontmatter has no non-empty description.", file.Path, 2, "Declare a concise skill description.")
	}
	if contract == nil {
		return
	}
	if name != "" && name != contract.Skill.Name {
		add(result, "SKIL-LINT-NAME-MISMATCH", LevelWarning, "Skill name mismatch",
			fmt.Sprintf("SKILL.md declares %q but the contract declares %q.", name, contract.Skill.Name),
			file.Path, 2, "Use the same skill name in both files.")
	}
	if description != "" && description != contract.Skill.Description {
		add(result, "SKIL-LINT-DESCRIPTION-MISMATCH", LevelWarning, "Skill description mismatch",
			"SKILL.md and the contract use different descriptions.", file.Path, 2,
			"Keep authoring metadata synchronized.")
	}
}

func lintContract(result *Result, artifact skil.Artifact, contract skil.SkillContract, contractPath string, format contracts.Format, profile Profile) {
	packageResult := packagecheck.ValidateAuthoring(artifact, contract)
	if profile == ProfilePublish {
		packageResult = packagecheck.Validate(artifact, contract)
	}
	for _, message := range packageResult.Errors {
		add(result, "SKIL-LINT-PACKAGE", LevelError, "Invalid authoring package",
			message, contractPath, 1, "Correct the package metadata or referenced entrypoint.")
	}
	if !namePattern.MatchString(contract.Skill.Name) {
		add(result, "SKIL-LINT-NAME-STYLE", LevelWarning, "Non-portable skill name",
			fmt.Sprintf("Skill name %q is not lowercase kebab-case.", contract.Skill.Name), contractPath, 1,
			"Use lowercase letters, digits, and single hyphens.")
	}
	if contract.Skill.Version != "" && !semverPattern.MatchString(contract.Skill.Version) {
		add(result, "SKIL-LINT-VERSION", LevelError, "Invalid semantic version",
			fmt.Sprintf("Skill version %q is not valid SemVer.", contract.Skill.Version), contractPath, 1,
			"Use a semantic version such as 1.2.3.")
	}
	if strings.TrimSpace(contract.Owner) == "" {
		add(result, "SKIL-LINT-OWNER", LevelWarning, "Missing owner",
			"The contract does not identify an accountable owner.", contractPath, 1,
			"Declare an owner or owning team.")
	}
	if format == contracts.FormatUniversal {
		return
	}
	lintCapabilities(result, contract.Capabilities, contractPath)
}

func lintCapabilities(result *Result, capabilities skil.Capabilities, contractPath string) {
	lists := []struct {
		name   string
		values []string
	}{
		{"filesystem.read", capabilities.Filesystem.Read},
		{"filesystem.write", capabilities.Filesystem.Write},
		{"filesystem.delete", capabilities.Filesystem.Delete},
		{"network.hosts", capabilities.Network.Hosts},
		{"commands.allow", capabilities.Commands.Allow},
		{"secrets.read", capabilities.Secrets.Read},
		{"environment.read", capabilities.Environment.Read},
		{"tools.allow", capabilities.Tools.Allow},
		{"tools.deny", capabilities.Tools.Deny},
		{"mcp.servers", capabilities.MCP.Servers},
		{"mcp.tools", capabilities.MCP.Tools},
	}
	for _, list := range lists {
		for _, value := range list.values {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				add(result, "SKIL-LINT-CAPABILITY-EMPTY", LevelError, "Empty capability entry",
					list.name+" contains an empty value.", contractPath, 1, "Remove the entry or declare an explicit bounded value.")
			}
			if trimmed == "*" || trimmed == "**" || trimmed == "**/*" {
				add(result, "SKIL-LINT-CAPABILITY-WILDCARD", LevelWarning, "Unbounded capability",
					fmt.Sprintf("%s contains wildcard %q.", list.name, value), contractPath, 1,
					"Replace broad wildcards with the smallest required allowlist.")
			}
		}
	}
	for _, item := range append(append([]string{}, capabilities.Filesystem.Read...), append(capabilities.Filesystem.Write, capabilities.Filesystem.Delete...)...) {
		clean := filepath.ToSlash(filepath.Clean(item))
		if filepath.IsAbs(item) || clean == ".." || strings.HasPrefix(clean, "../") {
			add(result, "SKIL-LINT-FILESYSTEM-SCOPE", LevelError, "Unsafe filesystem capability",
				fmt.Sprintf("Filesystem capability %q escapes the skill workspace.", item), contractPath, 1,
				"Use a relative, workspace-bounded path pattern.")
		}
	}
	if !capabilities.Network.Outbound && len(capabilities.Network.Hosts) > 0 {
		add(result, "SKIL-LINT-INACTIVE-HOSTS", LevelWarning, "Unused network allowlist",
			"network.hosts is populated while network.outbound is false.", contractPath, 1,
			"Remove the hosts or explicitly enable outbound networking.")
	}
	for _, host := range capabilities.Network.Hosts {
		if strings.Contains(host, "://") || strings.ContainsAny(host, "/?#") {
			add(result, "SKIL-LINT-HOST-FORMAT", LevelError, "Invalid network host",
				fmt.Sprintf("Network host %q must be a hostname, not a URL or path.", host), contractPath, 1,
				"Declare only a hostname or reviewed hostname pattern.")
		}
	}
	if !capabilities.Commands.Execute && len(capabilities.Commands.Allow) > 0 {
		add(result, "SKIL-LINT-INACTIVE-COMMANDS", LevelWarning, "Unused command allowlist",
			"commands.allow is populated while commands.execute is false.", contractPath, 1,
			"Remove the allowlist or explicitly enable command execution.")
	}
	denied := stringSet(capabilities.Tools.Deny)
	for _, tool := range capabilities.Tools.Allow {
		if denied[tool] {
			add(result, "SKIL-LINT-TOOL-CONFLICT", LevelError, "Conflicting tool policy",
				fmt.Sprintf("Tool %q is both allowed and denied.", tool), contractPath, 1,
				"Remove the tool from one of the two lists.")
		}
	}
	if capabilities.Agent.ExternalSideEffects && len(capabilities.Agent.ExternalTargets) == 0 {
		add(result, "SKIL-LINT-EXTERNAL-TARGETS", LevelWarning, "Unbounded external side effects",
			"External side effects are enabled without explicit targets.", contractPath, 1,
			"Declare the exact external systems the skill may change.")
	}
	if capabilities.Agent.ExternalSideEffects && !capabilities.Agent.ConfirmExternal {
		add(result, "SKIL-LINT-EXTERNAL-CONFIRMATION", LevelWarning, "External confirmation disabled",
			"External side effects are enabled without required confirmation.", contractPath, 1,
			"Require confirmation for external changes.")
	}
	if capabilities.Resources == (skil.ResourceLimits{}) {
		add(result, "SKIL-LINT-RESOURCE-LIMITS", LevelWarning, "Missing resource limits",
			"No runtime, memory, network, or tool-call limits are declared.", contractPath, 1,
			"Declare limits appropriate for the skill workload.")
	}
}

func lintStructuredFiles(result *Result, files []skil.File) {
	for _, file := range files {
		lower := strings.ToLower(filepath.ToSlash(file.Path))
		if lower == "package.json" || strings.HasSuffix(lower, "/package.json") ||
			strings.HasSuffix(lower, "mcp.json") || strings.HasSuffix(lower, "mcp-tools.lock.json") {
			if !json.Valid(file.Data) {
				add(result, "SKIL-LINT-JSON", LevelError, "Invalid JSON",
					"File is not valid JSON.", file.Path, 1, "Correct the JSON syntax before scanning.")
			}
		}
	}
}

func lintDependencyLocks(result *Result, files map[string]skil.File) {
	checks := []struct {
		manifest string
		locks    []string
		message  string
	}{
		{"package.json", []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"}, "JavaScript dependencies have no lockfile."},
		{"pyproject.toml", []string{"poetry.lock", "uv.lock", "pdm.lock"}, "Python project metadata has no supported lockfile."},
		{"go.mod", []string{"go.sum"}, "Go module dependencies have no go.sum."},
		{"cargo.toml", []string{"cargo.lock"}, "Cargo dependencies have no Cargo.lock."},
		{"gemfile", []string{"gemfile.lock"}, "Ruby dependencies have no Gemfile.lock."},
	}
	for _, check := range checks {
		manifest, exists := files[check.manifest]
		if !exists || hasAny(files, check.locks) {
			continue
		}
		add(result, "SKIL-LINT-LOCKFILE-MISSING", LevelWarning, "Missing dependency lockfile",
			check.message, manifest.Path, 1, "Generate and review a deterministic dependency lockfile.")
	}
}

func lintLocalLinks(result *Result, file skil.File, files map[string]skil.File) {
	for _, match := range localLink.FindAllSubmatchIndex(file.Data, -1) {
		target := string(file.Data[match[2]:match[3]])
		lower := strings.ToLower(target)
		if strings.HasPrefix(target, "#") || strings.Contains(target, "://") ||
			strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "data:") {
			continue
		}
		target = strings.SplitN(target, "#", 2)[0]
		target = strings.SplitN(target, "?", 2)[0]
		if target == "" {
			continue
		}
		resolved := path.Clean(path.Join(path.Dir(filepath.ToSlash(file.Path)), target))
		if resolved == ".." || strings.HasPrefix(resolved, "../") {
			add(result, "SKIL-LINT-LINK-ESCAPE", LevelError, "Escaping local link",
				fmt.Sprintf("Local link %q escapes the skill package.", target), file.Path, lineAt(file.Data, match[0]),
				"Link only to files contained in the skill package.")
		} else if _, exists := files[strings.ToLower(resolved)]; !exists {
			add(result, "SKIL-LINT-LINK-BROKEN", LevelWarning, "Broken local link",
				fmt.Sprintf("Local link %q does not resolve to a packaged file.", target), file.Path, lineAt(file.Data, match[0]),
				"Correct the link or include the referenced file.")
		}
	}
}

func parseFrontmatter(data []byte) (map[string]any, bool, error) {
	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	if !strings.HasPrefix(normalized, "---\n") {
		return nil, false, nil
	}
	end := strings.Index(normalized[4:], "\n---\n")
	if end < 0 {
		return nil, true, fmt.Errorf("opening frontmatter delimiter has no closing delimiter")
	}
	var metadata map[string]any
	if err := yaml.Unmarshal([]byte(normalized[4:4+end]), &metadata); err != nil {
		return nil, true, err
	}
	if metadata == nil {
		return nil, true, fmt.Errorf("frontmatter must be a YAML mapping")
	}
	return metadata, true, nil
}

func findContractPaths(files []skil.File) []string {
	var out []string
	for _, file := range files {
		normalized := strings.ToLower(filepath.ToSlash(file.Path))
		if contractNames[normalized] {
			out = append(out, file.Path)
		}
	}
	sort.Strings(out)
	return out
}

func fileIndex(files []skil.File) map[string]skil.File {
	out := make(map[string]skil.File, len(files))
	for _, file := range files {
		out[strings.ToLower(filepath.ToSlash(file.Path))] = file
	}
	return out
}

func hasAny(files map[string]skil.File, names []string) bool {
	for _, name := range names {
		if _, exists := files[name]; exists {
			return true
		}
	}
	return false
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func add(result *Result, ruleID string, level Level, title, message, file string, line int, remediation string) {
	sum := sha256.Sum256([]byte(strings.Join([]string{ruleID, file, fmt.Sprint(line), message}, "\x00")))
	fingerprint := hex.EncodeToString(sum[:])
	for _, issue := range result.Issues {
		if issue.Fingerprint == fingerprint {
			return
		}
	}
	result.Issues = append(result.Issues, Issue{
		RuleID: ruleID, Level: level, Title: title, Message: message,
		Location: skil.Location{File: file, StartLine: line}, Remediation: remediation,
		Fingerprint: fingerprint,
	})
}

func lineAt(data []byte, offset int) int {
	if offset < 0 || offset > len(data) {
		return 1
	}
	return 1 + bytes.Count(data[:offset], []byte{'\n'})
}

func rank(level Level) int {
	switch level {
	case LevelError:
		return 0
	case LevelWarning:
		return 1
	default:
		return 2
	}
}
