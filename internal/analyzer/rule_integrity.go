package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

type RuleArtifact struct {
	Rule              skil.Rule `json:"rule" yaml:"rule"`
	Version           string    `json:"version" yaml:"version"`
	Capability        string    `json:"capability" yaml:"capability"`
	DecisionSemantics string    `json:"decision_semantics" yaml:"decision_semantics"`
	Provenance        string    `json:"provenance" yaml:"provenance"`
	Digest            string    `json:"digest" yaml:"digest"`
}
type RulePackIntegrity struct {
	ID, Version, Provenance, Digest string
	Rules                           []RuleArtifact
	Complete                        bool
	Limitations                     []string
}

func ValidateRulePack(pack RulePackIntegrity, requiredRuleIDs []string) (RulePackIntegrity, error) {
	if pack.ID == "" || pack.Version == "" || pack.Provenance == "" {
		return pack, errors.New("rule pack identity, version, and provenance are required")
	}
	seen := map[string]bool{}
	for i := range pack.Rules {
		a := &pack.Rules[i]
		r := a.Rule
		if r.ID == "" || r.Title == "" || r.Category == "" || r.Severity == "" || r.Analysis == "" || a.Version == "" || a.Capability == "" || a.DecisionSemantics == "" || a.Provenance == "" {
			return pack, errors.New("rule artifact schema incomplete")
		}
		if seen[r.ID] {
			return pack, errors.New("duplicate rule ID")
		}
		seen[r.ID] = true
		sum := sha256.Sum256([]byte(strings.Join([]string{r.ID, r.Title, r.Category, string(r.Severity), r.Analysis, a.Version, a.Capability, a.DecisionSemantics, a.Provenance}, "\x00")))
		a.Digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	for _, id := range requiredRuleIDs {
		if !seen[id] {
			pack.Limitations = append(pack.Limitations, "required rule unavailable: "+id)
		}
	}
	sort.Slice(pack.Rules, func(i, j int) bool { return pack.Rules[i].Rule.ID < pack.Rules[j].Rule.ID })
	sort.Strings(pack.Limitations)
	h := sha256.New()
	h.Write([]byte(pack.ID + "\x00" + pack.Version + "\x00" + pack.Provenance))
	for _, a := range pack.Rules {
		h.Write([]byte("\x00" + a.Digest))
	}
	pack.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	pack.Complete = len(pack.Limitations) == 0
	if !pack.Complete {
		return pack, errors.New("required rule pack incomplete")
	}
	return pack, nil
}
