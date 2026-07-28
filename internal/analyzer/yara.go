package analyzer

import (
	"bytes"
	"context"
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

// YARA invokes an explicitly configured YARA binary with trusted source rules.
// Scanned bytes are written to narrow temporary files and never executed.
type YARA struct {
	Binary, RulesPath string
	Timeout           time.Duration
}

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

func (y *YARA) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.yara", Version: "1.0.0", Categories: []string{"malware"},
		AnalysisTypes: []string{"malware"}, SupportedTypes: []string{"*"}}
}

var yaraLine = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)`)
var safeRuleID = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

func (y *YARA) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
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
		command := exec.CommandContext(runContext, y.Binary, "--timeout=10", "--max-rules=100", "--no-warnings", y.RulesPath, tempPath)
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
