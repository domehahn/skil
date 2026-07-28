package baseline

import (
	"os"
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
type File struct {
	Version int     `json:"version" yaml:"version"`
	Entries []Entry `json:"entries" yaml:"entries"`
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
func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var file File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	err = dec.Decode(&file)
	return file, err
}
func Apply(findings []skil.Finding, file File, now time.Time) []skil.Finding {
	approved := map[string]Entry{}
	for _, entry := range file.Entries {
		if entry.ExpiresAt == nil || entry.ExpiresAt.After(now) {
			approved[entry.Fingerprint] = entry
		}
	}
	for i := range findings {
		if _, ok := approved[findings[i].Fingerprint]; ok {
			findings[i].Suppressed = true
		}
	}
	return findings
}
