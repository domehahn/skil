package baseline

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

type Entry struct {
	Fingerprint string     `json:"fingerprint" yaml:"fingerprint"`
	RuleID      string     `json:"rule_id" yaml:"rule_id"`
	Path        string     `json:"path" yaml:"path"`
	Reason      string     `json:"reason" yaml:"reason"`
	ApprovedBy  string     `json:"approved_by" yaml:"approved_by"`
	ApprovedAt  time.Time  `json:"approved_at" yaml:"approved_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

// Rule is an explicitly reviewed, drift-tolerant suppression selector. Every
// non-empty selector must match. Wildcards are deliberately limited to '*'
// and '?' and match path separators as well.
type Rule struct {
	RuleID     string     `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
	Path       string     `json:"path,omitempty" yaml:"path,omitempty"`
	Message    string     `json:"message,omitempty" yaml:"message,omitempty"`
	Reason     string     `json:"reason" yaml:"reason"`
	ApprovedBy string     `json:"approved_by" yaml:"approved_by"`
	ApprovedAt time.Time  `json:"approved_at" yaml:"approved_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

type File struct {
	Version        int     `json:"version" yaml:"version"`
	ScannerVersion string  `json:"scanner_version,omitempty" yaml:"scanner_version,omitempty"`
	SubjectDigest  string  `json:"subject_digest,omitempty" yaml:"subject_digest,omitempty"`
	Entries        []Entry `json:"entries" yaml:"entries"`
	Rules          []Rule  `json:"rules,omitempty" yaml:"rules,omitempty"`
}

func Create(findings []skil.Finding, approvedBy, reason string) File {
	now := time.Now().UTC()
	out := File{Version: 1, Entries: []Entry{}}
	for _, finding := range findings {
		out.Entries = append(out.Entries, Entry{Fingerprint: finding.Fingerprint, RuleID: finding.RuleID,
			Path: finding.Location.File, Reason: reason, ApprovedBy: approvedBy, ApprovedAt: now})
	}
	return out
}

func CreateForScan(scan skil.ScanResult, approvedBy, reason string) File {
	out := Create(scan.Findings, approvedBy, reason)
	out.Version = 2
	out.ScannerVersion = skil.Version
	out.SubjectDigest = scan.Artifact.SubjectDigest()
	return out
}
func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var file File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err = dec.Decode(&file); err != nil {
		return File{}, err
	}
	if file.Version != 1 && file.Version != 2 {
		return File{}, fmt.Errorf("unsupported baseline version %d", file.Version)
	}
	if len(file.Entries)+len(file.Rules) > 10_000 {
		return File{}, errors.New("baseline entry limit exceeded")
	}
	if file.Version == 2 && len(file.Entries) > 0 &&
		(file.ScannerVersion == "" || file.SubjectDigest == "") {
		return File{}, errors.New("version 2 exact baseline entries require scanner_version and subject_digest")
	}
	for index, entry := range file.Entries {
		if strings.TrimSpace(entry.Fingerprint) == "" || strings.TrimSpace(entry.Reason) == "" {
			return File{}, fmt.Errorf("baseline entry %d requires fingerprint and reason", index)
		}
	}
	for index, rule := range file.Rules {
		if strings.TrimSpace(rule.Reason) == "" ||
			rule.RuleID == "" && rule.Path == "" && rule.Message == "" {
			return File{}, fmt.Errorf("baseline rule %d requires a reason and at least one selector", index)
		}
		for _, value := range []string{rule.RuleID, rule.Path, rule.Message} {
			if len(value) > 1<<12 || strings.ContainsAny(value, "\x00\r\n") {
				return File{}, fmt.Errorf("baseline rule %d contains an invalid selector", index)
			}
			if _, err := compileGlob(value); err != nil {
				return File{}, fmt.Errorf("baseline rule %d: %w", index, err)
			}
		}
	}
	return file, nil
}
func Apply(findings []skil.Finding, file File, now time.Time) []skil.Finding {
	return ApplyForArtifact(findings, file, now, file.SubjectDigest)
}

func ApplyForArtifact(findings []skil.Finding, file File, now time.Time, subjectDigest string) []skil.Finding {
	approved := map[string]Entry{}
	exactAllowed := file.Version < 2 ||
		file.ScannerVersion == skil.Version && file.SubjectDigest != "" && file.SubjectDigest == subjectDigest
	if exactAllowed {
		for _, entry := range file.Entries {
			if entry.ExpiresAt == nil || entry.ExpiresAt.After(now) {
				approved[entry.Fingerprint] = entry
			}
		}
	}
	for i := range findings {
		if entry, ok := approved[findings[i].Fingerprint]; ok {
			findings[i].Suppressed = true
			findings[i].SuppressionReason = entry.Reason
			continue
		}
		for _, rule := range file.Rules {
			if (rule.ExpiresAt == nil || rule.ExpiresAt.After(now)) && matchesRule(findings[i], rule) {
				findings[i].Suppressed = true
				findings[i].SuppressionReason = rule.Reason
				break
			}
		}
	}
	return findings
}

func matchesRule(finding skil.Finding, rule Rule) bool {
	return globMatch(rule.RuleID, finding.RuleID, false) &&
		globMatch(rule.Path, finding.Location.File, false) &&
		globMatch(rule.Message, finding.Message+" "+evidenceText(finding.Evidence), true)
}

func evidenceText(evidence map[string]any) string {
	if evidence == nil {
		return ""
	}
	if value, ok := evidence["match"].(string); ok {
		return value
	}
	return ""
}

func globMatch(pattern, value string, fold bool) bool {
	if pattern == "" {
		return true
	}
	expression, err := compileGlob(pattern)
	if err != nil {
		return false
	}
	if fold {
		value = strings.ToLower(value)
		expression, _ = compileGlob(strings.ToLower(pattern))
	}
	return expression.MatchString(value)
}

func compileGlob(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return regexp.Compile("^.*$")
	}
	var expression strings.Builder
	expression.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteString(".")
		default:
			expression.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	expression.WriteString("$")
	return regexp.Compile(expression.String())
}
