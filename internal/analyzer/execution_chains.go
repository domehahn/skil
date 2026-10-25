package analyzer

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/domehahn/skil/internal/toolgrants"
	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

// PythonSurfaceKind classifies Python execution surfaces across source,
// extensionless shebang scripts, archive members, wrappers, and bytecode.
type PythonSurfaceKind string

const (
	PythonSurfaceNone              PythonSurfaceKind = "NONE"
	PythonSurfaceSourcePy          PythonSurfaceKind = "SOURCE_PY"
	PythonSurfaceSourcePyw         PythonSurfaceKind = "SOURCE_PYW"
	PythonSurfaceShebang           PythonSurfaceKind = "EXTENSIONLESS_SHEBANG"
	PythonSurfaceArchiveMember     PythonSurfaceKind = "ARCHIVE_MEMBER_SOURCE"
	PythonSurfaceBytecodePyc       PythonSurfaceKind = "BYTECODE_PYC"
	PythonSurfaceWrapperInvocation PythonSurfaceKind = "WRAPPER_INVOCATION"
)

var pythonShebangRE = regexp.MustCompile(`^#!\s*(?:/usr/bin/env\s+(?:-S\s+)?)?(?:/usr/(?:local/)?bin/)?python(?:\d+(?:\.\d+)?)?\b`)

func hasPythonShebang(data []byte) bool {
	firstLine := string(data)
	if idx := strings.IndexByte(firstLine, '\n'); idx >= 0 {
		firstLine = firstLine[:idx]
	}
	return pythonShebangRE.MatchString(strings.TrimSpace(firstLine))
}

func isPythonSourceFile(file skil.File) bool {
	ext := strings.ToLower(extension(file.Path))
	if ext == "py" || ext == "pyw" {
		return true
	}
	if ext == "" && hasPythonShebang(file.Data) {
		return true
	}
	return false
}

// ClassifyPythonSurface classifies a file's Python execution surface and
// whether it requires source AST analysis vs bytecode/completeness handling.
func ClassifyPythonSurface(file skil.File) PythonSurfaceKind {
	ext := strings.ToLower(extension(file.Path))
	inArchive := strings.Contains(file.Path, "!/") || file.ContainerDepth > 0
	switch {
	case ext == "pyc":
		return PythonSurfaceBytecodePyc
	case inArchive && (ext == "py" || ext == "pyw" || (ext == "" && hasPythonShebang(file.Data))):
		return PythonSurfaceArchiveMember
	case ext == "py":
		return PythonSurfaceSourcePy
	case ext == "pyw":
		return PythonSurfaceSourcePyw
	case ext == "" && hasPythonShebang(file.Data):
		return PythonSurfaceShebang
	case (ext == "sh" || ext == "bash" || ext == "md" || ext == "yaml" || ext == "yml") &&
		regexp.MustCompile(`\bpython(?:\d+(?:\.\d+)?)?\s+(?:-c|-m|\S+\.pyw?)\b`).Match(file.Data):
		return PythonSurfaceWrapperInvocation
	default:
		return PythonSurfaceNone
	}
}

// InterpretationAuthority distinguishes passive data/documentation from active
// instructions, configuration, or executable code.
type InterpretationAuthority string

const (
	AuthorityData           InterpretationAuthority = "DATA"
	AuthorityInstruction    InterpretationAuthority = "INSTRUCTION"
	AuthorityConfiguration  InterpretationAuthority = "CONFIGURATION"
	AuthorityExecutableCode InterpretationAuthority = "EXECUTABLE_CODE"
	AuthorityUnknown        InterpretationAuthority = "UNKNOWN"
)

// ClassifyLineAuthority determines the interpretation authority of a line in a file.
// Prose documentation and code comments are classified as DATA/INSTRUCTION rather
// than EXECUTABLE_CODE unless they occur inside an executable script or sink.
func ClassifyLineAuthority(file skil.File, line string, inFencedCodeBlock bool) InterpretationAuthority {
	ext := strings.ToLower(extension(file.Path))
	trimmed := strings.TrimSpace(line)
	if isPythonSourceFile(file) || ext == "sh" || ext == "bash" || ext == "js" || ext == "ts" || ext == "rb" {
		if strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "#!") {
			return AuthorityData
		}
		if strings.HasPrefix(trimmed, "//") {
			return AuthorityData
		}
		return AuthorityExecutableCode
	}
	if ext == "yaml" || ext == "yml" || ext == "json" || ext == "toml" {
		if strings.HasPrefix(trimmed, "#") {
			return AuthorityData
		}
		return AuthorityConfiguration
	}
	if ext == "md" {
		if inFencedCodeBlock {
			return AuthorityExecutableCode
		}
		return AuthorityInstruction
	}
	if ext == "txt" || ext == "csv" {
		return AuthorityData
	}
	return AuthorityUnknown
}

var (
	// Encoded execution chain patterns: decode primitive piped or passed into an execution sink.
	encodedShellChainRE = regexp.MustCompile(`(?i)(?:base64\s+(?:-d|--decode|-D)|base32\s+(?:-d|--decode)|xxd\s+-r|openssl\s+(?:enc\s+)?-d\b[^\n|]*)\s*\|\s*(?:(?:ba|z|da|k)?sh|python\d*|perl|ruby|node|pwsh|powershell|eval|source)\b`)
	encodedInlineExecRE = regexp.MustCompile(`(?i)(?:eval|exec|system|subprocess\.(?:run|call|Popen|check_output)|sh\s+-c|bash\s+-c|pwsh\s+-(?:e|enc|encodedcommand))\b[^\n]{0,160}(?:b64decode|b32decode|fromhex|base64\s+(?:-d|--decode)|atob\s*\()`)
	pwshEncodedFlagRE   = regexp.MustCompile(`(?i)\b(?:pwsh|powershell(?:\.exe)?)\b[^\n]{0,80}\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}`)

	// Whole-environment dump or bulk credential store exfiltration patterns.
	wholeEnvSourceRE = regexp.MustCompile(`(?i)(?:\b(?:printenv|env)\b\s*\||dict\s*\(\s*os\.environ\s*\)|os\.environ\.copy\s*\(\)|JSON\.stringify\s*\(\s*process\.env\s*\)|cat\s+[^\n|]*(?:\.env\b|\.ssh/id_(?:rsa|ed25519)|\.aws/credentials|\.npmrc|\.netrc))`)
	externalSinkRE   = regexp.MustCompile(`(?i)(?:\b(?:curl|wget|nc|netcat|socat)\b|requests\.(?:post|put)|urllib\.request\.urlopen|fetch\s*\(|https?://)`)
	benignSingleEnv  = regexp.MustCompile(`(?i)^[ \t]*[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:os\.getenv|os\.environ\.get)\s*\(\s*["'](?:PORT|HOST|LOG_LEVEL|DEBUG|ENV|NODE_ENV|TZ|LANG|HOME|PATH)["']`)
)

// AnalyzeEncodedExecutionAndExfiltration detects encoded decode-and-execute
// chains and whole-environment/credential exfiltration while avoiding false
// positives on benign encoding or benign single-variable config reads.
func AnalyzeEncodedExecutionAndExfiltration(file skil.File) []skil.Finding {
	var out []skil.Finding
	inFence := false
	for idx, line := range lines(file.Data) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		auth := ClassifyLineAuthority(file, line, inFence)
		// Comments and pure data lines are never treated as executable shell syntax.
		if auth == AuthorityData {
			continue
		}
		// In prose instruction lines (outside fenced code blocks), only flag if an explicit command sink is invoked.
		if encodedShellChainRE.MatchString(line) || encodedInlineExecRE.MatchString(line) || pwshEncodedFlagRE.MatchString(line) {
			rule := RulePattern{
				Rule: skil.Rule{
					ID:          "SKIL-EXEC-ENCODED-CHAIN",
					Title:       "Encoded payload decoded into execution sink",
					Category:    "dynamic-execution",
					Severity:    skil.SeverityCritical,
					Analysis:    "execution-chain",
					Description: "An encoded payload (Base64, Base32, hex, or OpenSSL) is decoded and routed directly into a shell or language execution sink.",
					Remediation: "Remove encoded execution chains and use reviewable, plaintext commands.",
				},
				Confidence: 0.96,
			}
			f := makeFinding(rule, file, idx+1, line)
			f.Evidence["interpretation_authority"] = string(auth)
			out = append(out, f)
		}

		if benignSingleEnv.MatchString(line) {
			continue
		}
		if wholeEnvSourceRE.MatchString(line) && externalSinkRE.MatchString(line) {
			rule := RulePattern{
				Rule: skil.Rule{
					ID:          "SKIL-EXFIL-ENV-DUMP",
					Title:       "Whole-environment or credential store exfiltration",
					Category:    "data-exfiltration",
					Severity:    skil.SeverityCritical,
					Analysis:    "execution-chain",
					Description: "The entire environment or a credential store (.env, SSH key, cloud credentials) is dumped and sent to an external network sink.",
					Remediation: "Never dump the full environment or credential files to external endpoints; read only declared configuration variables.",
				},
				Confidence: 0.97,
			}
			f := makeFinding(rule, file, idx+1, line)
			f.Evidence["interpretation_authority"] = string(auth)
			out = append(out, f)
		}
	}
	return out
}

// EffectiveFrontmatter represents the resolved YAML frontmatter of a skill document
// after anchor/alias expansion, merge-key resolution, and multiline folding.
type EffectiveFrontmatter struct {
	Name         string             `json:"name,omitempty"`
	Description  string             `json:"description,omitempty"`
	AllowedTools []string           `json:"allowed_tools,omitempty"`
	Hooks        map[string]any     `json:"hooks,omitempty"`
	RawEffective map[string]any     `json:"raw_effective,omitempty"`
	Grants       []toolgrants.Grant `json:"grants,omitempty"`
	Findings     []skil.Finding     `json:"findings,omitempty"`
}

// ExtractFrontmatterBytes extracts YAML frontmatter bounded by `---` delimiters
// at the start of a Markdown file, or returns the full buffer for `.yaml`/`.yml`.
func ExtractFrontmatterBytes(path string, data []byte) ([]byte, bool) {
	ext := strings.ToLower(extension(path))
	if ext == "yaml" || ext == "yml" {
		return data, true
	}
	text := string(data)
	if !strings.HasPrefix(text, "---\n") && !strings.HasPrefix(text, "---\r\n") {
		return nil, false
	}
	rest := text[4:]
	endIdx := strings.Index(rest, "\n---")
	if endIdx < 0 {
		return nil, false
	}
	return []byte(rest[:endIdx]), true
}

// ParseEffectiveFrontmatter validates YAML bounds (preventing alias bombs),
// resolves YAML anchors, aliases, merge keys (`<<`), and multiline strings,
// and audits effective `allowed-tools` / `allowed_tools` grants and embedded
// shell chains.
func ParseEffectiveFrontmatter(file skil.File) (*EffectiveFrontmatter, error) {
	ymlBytes, ok := ExtractFrontmatterBytes(file.Path, file.Data)
	if !ok {
		return nil, nil
	}
	if err := ValidateYAMLBounds(ymlBytes); err != nil {
		return nil, fmt.Errorf("frontmatter bounds check %s: %w", file.Path, err)
	}
	var effective map[string]any
	if err := yaml.Unmarshal(ymlBytes, &effective); err != nil {
		return nil, fmt.Errorf("unmarshal frontmatter %s: %w", file.Path, err)
	}
	result := &EffectiveFrontmatter{
		RawEffective: effective,
	}
	if name, ok := effective["name"].(string); ok {
		result.Name = name
	}
	if desc, ok := effective["description"].(string); ok {
		result.Description = desc
	}
	if hooks, ok := effective["hooks"].(map[string]any); ok {
		result.Hooks = hooks
	}

	// Collect allowed-tools / allowed_tools / tools after YAML alias/merge expansion.
	var rawTools []string
	for _, key := range []string{"allowed-tools", "allowed_tools", "tools"} {
		switch v := effective[key].(type) {
		case string:
			for _, part := range strings.Split(v, ",") {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					rawTools = append(rawTools, trimmed)
				}
			}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					rawTools = append(rawTools, strings.TrimSpace(s))
				}
			}
		}
	}
	sort.Strings(rawTools)
	result.AllowedTools = rawTools
	for _, rawGrant := range rawTools {
		parsed, err := toolgrants.Parse(rawGrant)
		if err != nil {
			rule := RulePattern{
				Rule: skil.Rule{
					ID:          "SKIL-AGENT-PERM-003",
					Title:       "Malformed or unsafe tool grant in effective frontmatter",
					Category:    "privilege-escalation",
					Severity:    skil.SeverityHigh,
					Analysis:    "frontmatter",
					Description: fmt.Sprintf("Tool grant %q in effective frontmatter is malformed and rejected without widening scope: %v", rawGrant, err),
					Remediation: "Use a well-formed scoped grant such as Bash(git status:*).",
				},
				Confidence: 0.98,
			}
			result.Findings = append(result.Findings, makeFinding(rule, file, 1, rawGrant))
			continue
		}
		for _, g := range parsed {
			result.Grants = append(result.Grants, g)
			if strings.EqualFold(g.Tool, "Bash") && g.Unrestricted {
				rule := RulePattern{
					Rule: skil.Rule{
						ID:          "SKIL-AGENT-PERM-003",
						Title:       "Unrestricted Bash tool grant in effective frontmatter",
						Category:    "privilege-escalation",
						Severity:    skil.SeverityHigh,
						Analysis:    "frontmatter",
						Description: "Effective frontmatter grants unrestricted Bash execution.",
						Remediation: "Scope Bash tool grants to exact command prefixes such as Bash(git status:*).",
					},
					Confidence: 0.98,
				}
				result.Findings = append(result.Findings, makeFinding(rule, file, 1, g.Raw))
			} else if strings.ContainsAny(g.Scope, ";&|`$()<>") {
				rule := RulePattern{
					Rule: skil.Rule{
						ID:          "SKIL-AGENT-PERM-003",
						Title:       "Shell metacharacters in scoped tool grant",
						Category:    "privilege-escalation",
						Severity:    skil.SeverityHigh,
						Analysis:    "frontmatter",
						Description: "Scoped tool grant contains shell metacharacters that could chain unintended commands.",
						Remediation: "Remove shell metacharacters from scoped tool grants.",
					},
					Confidence: 0.98,
				}
				result.Findings = append(result.Findings, makeFinding(rule, file, 1, g.Raw))
			}
		}
	}

	// Inspect effective string values (including folded multiline strings and merged anchors)
	// for encoded execution chains or dangerous shell invocations.
	var inspectValue func(v any)
	inspectValue = func(v any) {
		switch val := v.(type) {
		case string:
			virtualFile := skil.File{Path: file.Path, Data: []byte(val), SHA256: file.SHA256}
			for _, f := range AnalyzeEncodedExecutionAndExfiltration(virtualFile) {
				f.Evidence["source"] = "effective-yaml-frontmatter"
				result.Findings = append(result.Findings, f)
			}
		case []any:
			for _, child := range val {
				inspectValue(child)
			}
		case map[string]any:
			for _, k := range sortedMapKeys(val) {
				inspectValue(val[k])
			}
		}
	}
	inspectValue(effective)
	return result, nil
}

// BinaryInstructionProjection records bounded instruction-like text extracted
// from a binary or polyglot container without claiming full binary decompilation.
type BinaryInstructionProjection struct {
	File          string                  `json:"file"`
	Format        string                  `json:"format"`
	ByteOffset    int                     `json:"byte_offset"`
	Length        int                     `json:"length"`
	Snippet       string                  `json:"snippet"`
	Analyzability skil.AnalyzabilityState `json:"analyzability"`
	Finding       *skil.Finding           `json:"finding,omitempty"`
}

const MaxBinaryProjectionBytes = 256 * 1024

var binaryInjectionRE = regexp.MustCompile(`(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|system\s+override|(?:curl|wget)\s+https?://[^\s"'|]+\s*\|\s*(?:ba)?sh|\bbase64\s+(?:-d|--decode)\s*\|\s*(?:ba)?sh)`)

// DetectBinaryFormat Magic header detection for binary/polyglot containers.
func DetectBinaryFormat(data []byte) string {
	switch {
	case len(data) >= 6 && (bytes.Equal(data[:6], []byte("GIF87a")) || bytes.Equal(data[:6], []byte("GIF89a"))):
		return "GIF"
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}):
		return "PNG"
	case len(data) >= 5 && bytes.Equal(data[:5], []byte("%PDF-")):
		return "PDF"
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return "PE"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return "ELF"
	case len(data) >= 4 && (bytes.Equal(data[:4], []byte{0xfe, 0xed, 0xfa, 0xce}) ||
		bytes.Equal(data[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}) ||
		bytes.Equal(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(data[:4], []byte{0xce, 0xfa, 0xed, 0xfe})):
		return "Mach-O"
	default:
		return ""
	}
}

// ProjectBinaryInstructions performs bounded readable-ASCII extraction on
// recognized binary/polyglot containers to detect embedded prompt-injection or
// shell-execution instructions. It explicitly marks Analyzability as PARTIAL so
// binary string projection is never mistaken for full binary decompilation.
func ProjectBinaryInstructions(file skil.File) []BinaryInstructionProjection {
	format := DetectBinaryFormat(file.Data)
	if format == "" {
		return nil
	}
	data := file.Data
	if len(data) > MaxBinaryProjectionBytes {
		data = data[:MaxBinaryProjectionBytes]
	}
	var out []BinaryInstructionProjection
	locs := binaryInjectionRE.FindAllIndex(data, 10)
	for _, loc := range locs {
		snippet := string(data[loc[0]:loc[1]])
		rule := RulePattern{
			Rule: skil.Rule{
				ID:          "SKIL-ASSET-BINARY-INSTRUCTION",
				Title:       "Embedded instruction or execution payload in binary container",
				Category:    "asset-security",
				Severity:    skil.SeverityHigh,
				Analysis:    "binary-projection",
				Description: fmt.Sprintf("A %s binary container embeds readable prompt-injection or shell-execution instructions at byte offset %d.", format, loc[0]),
				Remediation: "Inspect and strip embedded instruction payloads from binary assets.",
			},
			Confidence: 0.91,
		}
		f := makeFinding(rule, file, 1, snippet)
		f.Evidence["binary_format"] = format
		f.Evidence["byte_offset"] = loc[0]
		f.Evidence["byte_length"] = loc[1] - loc[0]
		f.Evidence["analyzability"] = string(skil.AnalyzabilityPartial)
		out = append(out, BinaryInstructionProjection{
			File:          file.Path,
			Format:        format,
			ByteOffset:    loc[0],
			Length:        loc[1] - loc[0],
			Snippet:       snippet,
			Analyzability: skil.AnalyzabilityPartial,
			Finding:       &f,
		})
	}
	return out
}
