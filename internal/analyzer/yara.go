package analyzer

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

const maxYARAOutput = 1 << 20
const maxYARARulesBytes = 4 << 20
const maxYARARuleFiles = 256

// YARA invokes an explicitly configured YARA binary with trusted source rules.
// Scanned bytes are written to narrow temporary files and never executed.
type YARA struct {
	Binary, RulesPath string
	RulesData         []byte
	Timeout           time.Duration
}

//go:embed yara_rules/default.yar
var builtinYARARules []byte

func NewYARA(binary, rulesPath string) (*YARA, error) {
	if binary == "" {
		binary = "yara"
	}
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("find YARA binary: %w", err)
	}
	info, err := os.Lstat(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("open YARA rules: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("YARA rules must be a regular, non-symlink source file up to 1 MiB")
	}
	extension := strings.ToLower(filepath.Ext(rulesPath))
	if extension != ".yar" && extension != ".yara" {
		return nil, errors.New("only YARA source rules (.yar or .yara) are accepted")
	}
	rules, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, err
	}
	if bytes.IndexByte(rules, 0) >= 0 {
		return nil, errors.New("compiled or binary YARA rules are not accepted")
	}
	absoluteRules, err := filepath.Abs(rulesPath)
	if err != nil {
		return nil, err
	}
	return &YARA{Binary: resolved, RulesPath: absoluteRules, Timeout: 15 * time.Second}, nil
}

// NewYARADirectory loads a bounded, flat directory of trusted YARA source
// files. Sorting and materializing one temporary source keeps invocation
// deterministic and avoids giving the external scanner directory access.
func NewYARADirectory(binary, rulesDirectory string) (*YARA, error) {
	if binary == "" {
		binary = "yara"
	}
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("find YARA binary: %w", err)
	}
	info, err := os.Lstat(rulesDirectory)
	if err != nil {
		return nil, fmt.Errorf("open YARA rules directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("YARA rules directory must be a non-symlink directory")
	}
	entries, err := os.ReadDir(rulesDirectory)
	if err != nil {
		return nil, err
	}
	var combined bytes.Buffer
	count := 0
	for _, entry := range entries {
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension != ".yar" && extension != ".yara" {
			continue
		}
		path := filepath.Join(rulesDirectory, entry.Name())
		ruleInfo, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if ruleInfo.Mode()&os.ModeSymlink != 0 || !ruleInfo.Mode().IsRegular() || ruleInfo.Size() > 1<<20 {
			return nil, fmt.Errorf("YARA rule %q must be a regular, non-symlink source file up to 1 MiB", entry.Name())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil, fmt.Errorf("YARA rule %q is compiled or binary", entry.Name())
		}
		if combined.Len()+len(data)+2 > maxYARARulesBytes {
			return nil, errors.New("combined YARA rules exceed 4 MiB")
		}
		combined.Write(data)
		combined.WriteString("\n\n")
		count++
		if count > maxYARARuleFiles {
			return nil, errors.New("YARA rules file-count limit exceeded")
		}
	}
	if count == 0 {
		return nil, errors.New("YARA rules directory contains no .yar or .yara source files")
	}
	return &YARA{Binary: resolved, RulesData: combined.Bytes(), Timeout: 15 * time.Second}, nil
}

// NewBuiltinYARA enables skil's independently maintained conservative rule
// pack. It is opt-in because invoking a host malware engine is an external
// execution boundary.
func NewBuiltinYARA(binary string) (*YARA, error) {
	if binary == "" {
		binary = "yara"
	}
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("find YARA binary: %w", err)
	}
	return &YARA{Binary: resolved, RulesData: append([]byte(nil), builtinYARARules...), Timeout: 15 * time.Second}, nil
}

func (y *YARA) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.yara", Version: "1.0.0", Categories: []string{"malware"},
		AnalysisTypes: []string{"malware"}, SupportedTypes: []string{"*"}}
}

var yaraLine = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)`)
var safeRuleID = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

func (y *YARA) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	rulesPath := y.RulesPath
	if len(y.RulesData) > 0 {
		rules, err := os.CreateTemp("", "skil-yara-rules-*.yar")
		if err != nil {
			return nil, err
		}
		rulesPath = rules.Name()
		if err := rules.Chmod(0o600); err != nil {
			_ = rules.Close()
			_ = os.Remove(rulesPath)
			return nil, err
		}
		_, writeErr := rules.Write(y.RulesData)
		closeErr := rules.Close()
		if writeErr != nil || closeErr != nil {
			_ = os.Remove(rulesPath)
			return nil, errors.Join(writeErr, closeErr)
		}
		defer os.Remove(rulesPath)
	}
	if rulesPath == "" {
		return nil, errors.New("YARA rules are not configured")
	}
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		temp, err := os.CreateTemp("", "skil-yara-*")
		if err != nil {
			return nil, err
		}
		tempPath := temp.Name()
		_, err = temp.Write(file.Data)
		closeErr := temp.Close()
		if err != nil || closeErr != nil {
			_ = os.Remove(tempPath)
			return nil, errors.Join(err, closeErr)
		}
		timeout := y.Timeout
		if timeout <= 0 {
			timeout = 15 * time.Second
		}
		runContext, cancel := context.WithTimeout(ctx, timeout)
		command := exec.CommandContext(runContext, y.Binary, "--timeout=10", "--max-rules=100", "--no-warnings", rulesPath, tempPath)
		var stdout limitedBuffer
		var stderr limitedBuffer
		stdout.limit, stderr.limit = maxYARAOutput, maxYARAOutput
		command.Stdout, command.Stderr = &stdout, &stderr
		runErr := command.Run()
		contextErr := runContext.Err()
		cancel()
		_ = os.Remove(tempPath)
		if contextErr != nil {
			return nil, fmt.Errorf("YARA timed out scanning %s", file.Path)
		}
		if runErr != nil {
			return nil, fmt.Errorf("YARA failed scanning %s: %w: %s", file.Path, runErr, strings.TrimSpace(stderr.String()))
		}
		for _, line := range strings.Split(stdout.String(), "\n") {
			match := yaraLine.FindStringSubmatch(strings.TrimSpace(line))
			if len(match) < 2 {
				continue
			}
			name := match[1]
			id := "SKIL-YARA-" + strings.ToUpper(safeRuleID.ReplaceAllString(name, "-"))
			rule := RulePattern{Rule: skil.Rule{ID: id, Title: "YARA malware signature: " + name,
				Category: "malware", Severity: skil.SeverityCritical, Description: "Trusted YARA rules matched the artifact.",
				Analysis: "yara", Remediation: "Quarantine the artifact and investigate the matching payload."}, Confidence: .99}
			finding := makeFinding(rule, file, 0, name)
			finding.Evidence["yara_rule"] = name
			out = append(out, finding)
		}
	}
	return out, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Buffer.Len()+len(p) > b.limit {
		remaining := b.limit - b.Buffer.Len()
		if remaining > 0 {
			_, _ = b.Buffer.Write(p[:remaining])
		}
		return len(p), errors.New("command output limit exceeded")
	}
	return b.Buffer.Write(p)
}
