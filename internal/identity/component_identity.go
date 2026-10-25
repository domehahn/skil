package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

type ConstraintKind string

const (
	ConstraintExact       ConstraintKind = "EXACT"
	ConstraintRange       ConstraintKind = "RANGE"
	ConstraintFloating    ConstraintKind = "FLOATING"
	ConstraintLatest      ConstraintKind = "LATEST"
	ConstraintWildcard    ConstraintKind = "WILDCARD"
	ConstraintUnspecified ConstraintKind = "UNSPECIFIED"
	ConstraintUnknown     ConstraintKind = "UNKNOWN"
)

type ComponentIdentity struct {
	Ecosystem        string         `json:"ecosystem" yaml:"ecosystem"`
	Namespace        string         `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Name             string         `json:"name" yaml:"name"`
	Constraint       string         `json:"constraint,omitempty" yaml:"constraint,omitempty"`
	ConstraintKind   ConstraintKind `json:"constraint_kind" yaml:"constraint_kind"`
	ResolvedIdentity string         `json:"resolved_identity,omitempty" yaml:"resolved_identity,omitempty"`
	ResolvedVersion  string         `json:"resolved_version,omitempty" yaml:"resolved_version,omitempty"`
	ResolvedDigest   string         `json:"resolved_digest,omitempty" yaml:"resolved_digest,omitempty"`
	Provenance       []string       `json:"provenance,omitempty" yaml:"provenance,omitempty"`
	Digest           string         `json:"digest" yaml:"digest"`
}

var exactVersion = regexp.MustCompile(`^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$`)
var floatingVersion = regexp.MustCompile(`(^|\.)x($|\.)`)

func ClassifyConstraint(value string) ConstraintKind {
	v := strings.TrimSpace(strings.ToLower(value))
	switch v {
	case "":
		return ConstraintUnspecified
	case "latest":
		return ConstraintLatest
	case "*", "x":
		return ConstraintWildcard
	case "main", "master", "head", "trunk":
		return ConstraintFloating
	}
	if strings.Contains(v, "*") || floatingVersion.MatchString(v) {
		return ConstraintFloating
	}
	if strings.HasPrefix(v, "^") || strings.HasPrefix(v, "~") || strings.ContainsAny(v, "<>=,") {
		return ConstraintRange
	}
	if exactVersion.MatchString(v) || regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(v) || strings.HasPrefix(v, "sha256:") {
		return ConstraintExact
	}
	return ConstraintUnknown
}

func FinalizeComponent(c ComponentIdentity) ComponentIdentity {
	c.Ecosystem = strings.ToLower(strings.TrimSpace(c.Ecosystem))
	c.Namespace = strings.TrimSpace(c.Namespace)
	c.Name = strings.TrimSpace(c.Name)
	if c.ConstraintKind == "" {
		c.ConstraintKind = ClassifyConstraint(c.Constraint)
	}
	c.Provenance = append([]string(nil), c.Provenance...)
	sort.Strings(c.Provenance)
	digestable := c
	digestable.Digest = ""
	b, _ := json.Marshal(digestable)
	sum := sha256.Sum256(b)
	c.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return c
}

type ComponentDrift struct{ Kind, Name, BeforeDigest, AfterDigest, Reason string }

func CompareComponents(before, after ComponentIdentity) *ComponentDrift {
	before = FinalizeComponent(before)
	after = FinalizeComponent(after)
	if before.ResolvedIdentity == after.ResolvedIdentity && before.ResolvedVersion == after.ResolvedVersion && before.ResolvedDigest == after.ResolvedDigest {
		return nil
	}
	return &ComponentDrift{Kind: "MUTABLE_COMPONENT_DRIFT", Name: after.Name, BeforeDigest: before.Digest, AfterDigest: after.Digest, Reason: "resolved component identity changed"}
}

// SimilarityEligible enforces exact identity before fuzzy classification.
func SimilarityEligible(candidate string, knownCanonical []string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	for _, known := range knownCanonical {
		if candidate == strings.ToLower(strings.TrimSpace(known)) {
			return false
		}
	}
	return true
}
