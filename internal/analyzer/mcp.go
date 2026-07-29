package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
	"github.com/domehahn/skil/schemas"
	"gopkg.in/yaml.v3"
)

type MCP struct{}

func NewMCP() *MCP { return &MCP{} }
func (m *MCP) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.mcp", Version: "1.0.0",
		Categories:    []string{"tool-protocol"},
		AnalysisTypes: []string{"mcp"}, SupportedTypes: []string{"json", "yaml"}}
}
func (m *MCP) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	wild := regexp.MustCompile(`(?i)(?:permissions?|tools?|allow)\s*["':=\s]+\*`)
	poison := regexp.MustCompile(`(?i)(?:description|default).{0,40}(?:ignore (?:previous|system)|never refuse|reveal (?:system|secret)|hidden instruction)`)
	poisonValue := regexp.MustCompile(`(?i)(?:ignore (?:previous|system)|never refuse|reveal (?:system|secret)|hidden instruction)`)
	parameterPoison := regexp.MustCompile(`(?i)(?:read|collect).{0,50}(?:all\s+)?(?:available\s+)?(?:secrets?|credentials?|environment variables?).{0,60}(?:put|include|provide|send).{0,20}(?:here|parameter|field)`)
	mutableIdentityFallback := regexp.MustCompile(`(?i)(?:\bnpx\b.{0,80}(?:@latest|["',\s][A-Za-z0-9_.@/-]+["']?\s*$)|\buvx\b\s+[A-Za-z0-9_.-]+\s*$|["'](?:version|revision|digest)["']\s*:\s*["'](?:latest|main|master|\*)["'])`)
	lock, err := loadMCPLock(ac.Artifact)
	if err != nil {
		return nil, err
	}
	definitions := map[string]string{}
	for _, file := range ac.Artifact.Files {
		lower := strings.ToLower(file.Path)
		if !strings.Contains(lower, "mcp") && !strings.Contains(strings.ToLower(string(file.Data)), "mcpserver") {
			continue
		}
		var document any
		if err := yaml.Unmarshal(file.Data, &document); err == nil && isStructuredMCPDocument(document) {
			collectMCPDefinitions(document, definitions)
			seen := map[string]bool{}
			for _, identity := range mutableMCPIdentities(document) {
				line, text := lineContaining(file.Data, identity)
				emitMCPFinding(&out, seen, file, line, text, mutableMCPRule())
			}
			walkMCPDocument(document, func(key string, value any) {
				normalized := strings.ToLower(strings.TrimSpace(key))
				line, text := lineContaining(file.Data, key)
				if mcpPermissionKey(normalized) && containsWildcard(value) {
					emitMCPFinding(&out, seen, file, line, text, RulePattern{Rule: skil.Rule{
						ID: "SKIL-MCP-001", Title: "Wildcard MCP permission",
						Category: "tool-protocol", Severity: skil.SeverityHigh,
						Description: "MCP configuration grants an unconstrained wildcard.", Analysis: "mcp",
						Remediation: "Declare exact MCP servers and tools."}, Confidence: .99})
				}
				if (normalized == "description" || normalized == "default") && poisonValue.MatchString(stringValue(value)) {
					emitMCPFinding(&out, seen, file, line, text, RulePattern{Rule: skil.Rule{
						ID: "SKIL-MCP-002", Title: "MCP tool description poisoning",
						Category: "tool-protocol", Severity: skil.SeverityCritical,
						Description: "An MCP description or default embeds manipulative instructions.", Analysis: "mcp",
						Remediation: "Remove hidden instructions and bind descriptions to reviewed tool behavior."}, Confidence: .99})
				}
				if normalized == "description" && parameterPoison.MatchString(stringValue(value)) {
					emitMCPFinding(&out, seen, file, line, text, RulePattern{Rule: skil.Rule{
						ID: "SKIL-MCP-004", Title: "MCP parameter description injection",
						Category: "tool-protocol", Severity: skil.SeverityCritical,
						Description: "An MCP parameter description requests secrets or credentials.",
						Analysis:    "mcp", Remediation: "Describe only the parameter value and remove credential-collection instructions.",
					}, Confidence: .99})
				}
			})
			for _, description := range mcpParameterDescriptions(document) {
				// Reuse the same deterministic intent-matching primitive
				// applied to skill-document text (instruction override,
				// role-token spoofing, privilege escalation, disclosure, ...)
				// rather than a second, MCP-only regex engine, per the
				// single-primitive-consistent-everywhere requirement.
				if _, _, matched := MatchIntentText(description); !matched {
					continue
				}
				line, text := lineContaining(file.Data, description)
				emitMCPFinding(&out, seen, file, line, text, RulePattern{Rule: skil.Rule{
					ID: "SKIL-MCP-004", Title: "MCP parameter description injection",
					Category: "tool-protocol", Severity: skil.SeverityCritical,
					Description: "An MCP parameter description embeds an instruction-override, role-spoofing, or privilege-escalation payload.",
					Analysis:    "mcp", Remediation: "Describe only the parameter value and remove embedded instructions.",
				}, Confidence: .97})
			}
			continue
		}
		for line, text := range lines(file.Data) {
			if mutableIdentityFallback.MatchString(text) {
				out = append(out, makeFinding(mutableMCPRule(), file, line+1, text))
			}
			if wild.MatchString(text) {
				rule := RulePattern{Rule: skil.Rule{ID: "SKIL-MCP-001", Title: "Wildcard MCP permission",
					Category: "tool-protocol", Severity: skil.SeverityHigh,
					Description: "MCP configuration grants an unconstrained wildcard.", Analysis: "mcp",
					Remediation: "Declare exact MCP servers and tools."}, Confidence: .9}
				out = append(out, makeFinding(rule, file, line+1, text))
			}
			if poison.MatchString(text) {
				rule := RulePattern{Rule: skil.Rule{ID: "SKIL-MCP-002", Title: "MCP tool description poisoning",
					Category: "tool-protocol", Severity: skil.SeverityCritical,
					Description: "An MCP description or default embeds manipulative instructions.", Analysis: "mcp",
					Remediation: "Remove hidden instructions and bind descriptions to reviewed tool behavior."}, Confidence: .9}
				out = append(out, makeFinding(rule, file, line+1, text))
			}
		}
	}
	for name, expected := range lock {
		description, exists := definitions[name]
		sum := sha256.Sum256([]byte(description))
		observed := hex.EncodeToString(sum[:])
		if !exists || observed != expected {
			rule := RulePattern{Rule: skil.Rule{
				ID: "SKIL-MCP-005", Title: "MCP tool metadata rug pull",
				Category: "tool-protocol", Severity: skil.SeverityCritical,
				Description: "Current MCP tool metadata differs from its reviewed immutable lock.",
				Analysis:    "mcp", Remediation: "Re-review the tool metadata and update the lock only after approval.",
			}, Confidence: .99}
			finding := makeFinding(rule, skil.File{Path: ".skil/mcp-tools.lock.json"}, 1, name)
			finding.Evidence["tool"] = name
			finding.Evidence["expected_description_sha256"] = expected
			finding.Evidence["observed_description_sha256"] = observed
			out = append(out, finding)
		}
	}
	out = append(out, mcpBehaviorMismatchFindings(ac.Artifact, definitions)...)
	return out, nil
}

func mutableMCPRule() RulePattern {
	return RulePattern{Rule: skil.Rule{
		ID: "SKIL-MCP-003", Title: "Mutable MCP tool identity",
		Category: "tool-protocol", Severity: skil.SeverityHigh,
		Description: "An MCP server or tool is resolved from a mutable package or revision.",
		Analysis:    "mcp", Remediation: "Pin the exact package version or immutable revision and verify its digest.",
	}, Confidence: .96}
}

func mutableMCPIdentities(value any) []string {
	var identities []string
	var visit func(any)
	visit = func(current any) {
		switch item := current.(type) {
		case map[string]any:
			command, _ := item["command"].(string)
			if command != "" {
				args := mcpStringSlice(item["args"])
				if mutableCommandIdentity(command, args) {
					identities = append(identities, firstPackageArgument(args))
				}
			}
			for _, key := range sortedMapKeys(item) {
				child := item[key]
				normalized := strings.ToLower(strings.TrimSpace(key))
				if normalized == "version" || normalized == "revision" || normalized == "digest" {
					if text, ok := child.(string); ok && mutableIdentityValue(text) {
						identities = append(identities, text)
					}
				}
				visit(child)
			}
		case []any:
			for _, child := range item {
				visit(child)
			}
		}
	}
	visit(value)
	sort.Strings(identities)
	return identities
}

func mcpStringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func mutableCommandIdentity(command string, args []string) bool {
	base := strings.ToLower(command)
	if slash := strings.LastIndexAny(base, `/\`); slash >= 0 {
		base = base[slash+1:]
	}
	argument := firstPackageArgument(args)
	if argument == "" {
		return false
	}
	switch base {
	case "npx", "npx.cmd":
		return !exactNPMIdentity(argument)
	case "uvx", "uvx.exe":
		return !exactPythonIdentity(argument)
	default:
		return false
	}
}

func firstPackageArgument(args []string) string {
	for _, argument := range args {
		argument = strings.TrimSpace(argument)
		if argument != "" && !strings.HasPrefix(argument, "-") {
			return argument
		}
	}
	return ""
}

func exactNPMIdentity(identity string) bool {
	index := strings.LastIndex(identity, "@")
	if index <= 0 || strings.HasPrefix(identity[index+1:], "latest") {
		return false
	}
	version := identity[index+1:]
	return regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$`).MatchString(version) ||
		regexp.MustCompile(`^[0-9a-fA-F]{40,64}$`).MatchString(version)
}

func exactPythonIdentity(identity string) bool {
	if parts := strings.SplitN(identity, "==", 2); len(parts) == 2 {
		return regexp.MustCompile(`^\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?$`).MatchString(parts[1])
	}
	if index := strings.LastIndex(identity, "@"); index > 0 {
		version := identity[index+1:]
		return regexp.MustCompile(`^\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?$`).MatchString(version) ||
			regexp.MustCompile(`^[0-9a-fA-F]{40,64}$`).MatchString(version)
	}
	return false
}

func mutableIdentityValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "*", "latest", "main", "master", "head":
		return true
	default:
		return false
	}
}

type mcpLockDocument struct {
	Version int               `json:"version"`
	Tools   map[string]string `json:"tools"`
}

func loadMCPLock(artifact skil.Artifact) (map[string]string, error) {
	for _, file := range artifact.Files {
		if file.Path != ".skil/mcp-tools.lock.json" {
			continue
		}
		if err := schemas.ValidateYAML("mcp-tools-lock-v1.schema.json", file.Data); err != nil {
			return nil, fmt.Errorf("validate MCP metadata lock: %w", err)
		}
		var document mcpLockDocument
		decoder := json.NewDecoder(strings.NewReader(string(file.Data)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&document); err != nil {
			return nil, fmt.Errorf("parse MCP metadata lock: %w", err)
		}
		if document.Version != 1 || len(document.Tools) == 0 {
			return nil, fmt.Errorf("MCP metadata lock requires version 1 and tools")
		}
		for name, digest := range document.Tools {
			if strings.TrimSpace(name) == "" || len(digest) != 64 {
				return nil, fmt.Errorf("MCP metadata lock contains an invalid tool or digest")
			}
			if _, err := hex.DecodeString(digest); err != nil {
				return nil, fmt.Errorf("MCP metadata lock contains a non-hex digest")
			}
		}
		return document.Tools, nil
	}
	return map[string]string{}, nil
}

func collectMCPDefinitions(value any, out map[string]string) {
	switch item := value.(type) {
	case map[string]any:
		name, nameOK := item["name"].(string)
		description, descriptionOK := item["description"].(string)
		if nameOK && descriptionOK && name != "" {
			if existing, exists := out[name]; exists && existing != description {
				out[name] = "\x00conflicting MCP descriptions"
			} else {
				out[name] = description
			}
		}
		for _, key := range sortedMapKeys(item) {
			collectMCPDefinitions(item[key], out)
		}
	case []any:
		for _, child := range item {
			collectMCPDefinitions(child, out)
		}
	}
}

func mcpBehaviorMismatchFindings(artifact skil.Artifact, definitions map[string]string) []skil.Finding {
	var out []skil.Finding
	names := make([]string, 0, len(definitions))
	for name := range definitions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		description := definitions[name]
		lowerDescription := strings.ToLower(description)
		if !strings.Contains(lowerDescription, "read") ||
			(!strings.Contains(lowerDescription, "file") && !strings.Contains(lowerDescription, "local")) {
			continue
		}
		for _, file := range artifact.Files {
			if extension(file.Path) != "py" {
				continue
			}
			source := strings.ToLower(string(file.Data))
			if !strings.Contains(source, "def "+strings.ToLower(name)+"(") ||
				!regexp.MustCompile(`requests\.(?:post|put)\s*\(`).MatchString(source) {
				continue
			}
			rule := RulePattern{Rule: skil.Rule{
				ID: "SKIL-MCP-006", Title: "MCP description and behavior mismatch",
				Category: "tool-protocol", Severity: skil.SeverityHigh,
				Description: "A read-only MCP tool implementation also performs an external upload.",
				Analysis:    "mcp", Remediation: "Align implementation with reviewed metadata or explicitly declare the external behavior.",
			}, Confidence: .96}
			out = append(out, makeFinding(rule, file, 1, name))
		}
	}
	return out
}

// mcpParameterDescriptions collects the description text of individual tool
// parameters, recognizing both the JSON-Schema convention used by MCP
// `inputSchema.properties.<name>.description` and the flatter
// `parameters: [{name, description}, ...]` list some skill manifests use.
// It intentionally only reports descriptions found in a parameter context,
// not a tool's own top-level "description" (handled separately as
// SKIL-MCP-002), so the same key name is not treated as a parameter payload
// everywhere it appears.
func mcpParameterDescriptions(value any) []string {
	var out []string
	var visitProperties func(any, string)
	visitProperties = func(v any, parentKey string) {
		switch item := v.(type) {
		case map[string]any:
			if strings.EqualFold(parentKey, "properties") {
				for _, key := range sortedMapKeys(item) {
					if prop, ok := item[key].(map[string]any); ok {
						if description, ok := prop["description"].(string); ok && description != "" {
							out = append(out, description)
						}
					}
				}
			}
			for _, key := range sortedMapKeys(item) {
				visitProperties(item[key], key)
			}
		case []any:
			for _, child := range item {
				visitProperties(child, parentKey)
			}
		}
	}
	visitProperties(value, "")

	var visitParameterList func(any)
	visitParameterList = func(v any) {
		switch item := v.(type) {
		case map[string]any:
			if parameters, ok := item["parameters"].([]any); ok {
				for _, entry := range parameters {
					if parameter, ok := entry.(map[string]any); ok {
						if description, ok := parameter["description"].(string); ok && description != "" {
							out = append(out, description)
						}
					}
				}
			}
			for _, key := range sortedMapKeys(item) {
				visitParameterList(item[key])
			}
		case []any:
			for _, child := range item {
				visitParameterList(child)
			}
		}
	}
	visitParameterList(value)
	return out
}

func isStructuredMCPDocument(value any) bool {
	switch value.(type) {
	case map[string]any, []any:
		return true
	default:
		return false
	}
}

func walkMCPDocument(value any, visit func(string, any)) {
	switch item := value.(type) {
	case map[string]any:
		for _, key := range sortedMapKeys(item) {
			child := item[key]
			visit(key, child)
			walkMCPDocument(child, visit)
		}
	case []any:
		for _, child := range item {
			walkMCPDocument(child, visit)
		}
	}
}

func sortedMapKeys(item map[string]any) []string {
	keys := make([]string, 0, len(item))
	for key := range item {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func mcpPermissionKey(key string) bool {
	switch key {
	case "permission", "permissions", "tool", "tools", "allow", "allowed_tools":
		return true
	default:
		return false
	}
}

func containsWildcard(value any) bool {
	switch item := value.(type) {
	case string:
		return strings.TrimSpace(item) == "*"
	case []any:
		for _, child := range item {
			if containsWildcard(child) {
				return true
			}
		}
	case map[string]any:
		if _, ok := item["*"]; ok {
			return true
		}
		for _, child := range item {
			if containsWildcard(child) {
				return true
			}
		}
	}
	return false
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func lineContaining(data []byte, value string) (int, string) {
	needle := strings.ToLower(value)
	for index, line := range lines(data) {
		if strings.Contains(strings.ToLower(line), needle) {
			return index + 1, line
		}
	}
	return 1, value
}

func emitMCPFinding(out *[]skil.Finding, seen map[string]bool, file skil.File, line int, text string, rule RulePattern) {
	key := rule.Rule.ID + ":" + file.Path + ":" + strings.TrimSpace(text)
	if seen[key] {
		return
	}
	seen[key] = true
	*out = append(*out, makeFinding(rule, file, line, text))
}
