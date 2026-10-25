package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// SubjectCacheIdentity binds cached analysis artifacts to the complete
// provenance of the subject and the exact analyzer/rule/policy configuration.
// Identical content bytes from different physical or virtual containers (e.g.
// a regular file vs an archive member inside outer.zip!/inner.zip) must never
// share a cache key without matching ancestry and configuration digests.
type SubjectCacheIdentity struct {
	SourceType             string   `json:"source_type"`
	SourceDigest           string   `json:"source_digest"`
	PhysicalPath           string   `json:"physical_path"`
	VirtualArchiveAncestry []string `json:"virtual_archive_ancestry,omitempty"`
	MemberPath             string   `json:"member_path,omitempty"`
	ContentSHA256          string   `json:"content_sha256"`
	AnalyzerID             string   `json:"analyzer_id"`
	AnalyzerVersion        string   `json:"analyzer_version"`
	RulePackDigest         string   `json:"rule_pack_digest"`
	ConfigDigest           string   `json:"config_digest"`
	PolicyDigest           string   `json:"policy_digest"`
}

// Validate ensures no mandatory cache-binding dimension is omitted.
func (id SubjectCacheIdentity) Validate() error {
	if strings.TrimSpace(id.SourceType) == "" {
		return errors.New("cache identity requires source_type")
	}
	if strings.TrimSpace(id.SourceDigest) == "" {
		return errors.New("cache identity requires source_digest")
	}
	if strings.TrimSpace(id.PhysicalPath) == "" {
		return errors.New("cache identity requires physical_path")
	}
	if strings.TrimSpace(id.ContentSHA256) == "" {
		return errors.New("cache identity requires content_sha256")
	}
	if strings.TrimSpace(id.AnalyzerID) == "" || strings.TrimSpace(id.AnalyzerVersion) == "" {
		return errors.New("cache identity requires analyzer_id and analyzer_version")
	}
	if strings.TrimSpace(id.RulePackDigest) == "" || strings.TrimSpace(id.ConfigDigest) == "" || strings.TrimSpace(id.PolicyDigest) == "" {
		return errors.New("cache identity requires rule_pack_digest, config_digest, and policy_digest")
	}
	for i, parent := range id.VirtualArchiveAncestry {
		if strings.TrimSpace(parent) == "" {
			return fmt.Errorf("cache identity virtual_archive_ancestry[%d] is empty", i)
		}
	}
	if len(id.VirtualArchiveAncestry) > 0 && strings.TrimSpace(id.MemberPath) == "" {
		return errors.New("virtual archive member requires member_path")
	}
	return nil
}

// BuildCacheKey computes a deterministic, collision-resistant cache key bound
// to source identity, container ancestry, content digest, and analyzer/rule/policy state.
func BuildCacheKey(id SubjectCacheIdentity) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(id)
	if err != nil {
		return "", fmt.Errorf("marshal cache identity: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "skil-cache-v1:sha256:" + hex.EncodeToString(sum[:]), nil
}

// SubjectIdentityForFile derives the physical or virtual subject identity for a
// loaded artifact file, preserving nested container ancestry.
func SubjectIdentityForFile(art skil.Artifact, file skil.File, analyzerID, analyzerVer, ruleDigest, configDigest, policyDigest string) SubjectCacheIdentity {
	sourceType := "directory"
	sourceDigest := art.Digest
	if art.PackageDigest != "" {
		sourceType = "archive"
		sourceDigest = art.PackageDigest
	}
	physicalPath := file.Path
	memberPath := ""
	var ancestry []string
	if strings.Contains(file.Path, "!/") {
		parts := strings.Split(file.Path, "!/")
		physicalPath = parts[0]
		memberPath = parts[len(parts)-1]
		for i := 0; i < len(parts)-1; i++ {
			ancestry = append(ancestry, parts[i])
		}
		if file.ContainerParentSHA256 != "" {
			ancestry = append(ancestry, "parent_sha256:"+file.ContainerParentSHA256)
		}
		if file.ContainerDepth > 0 {
			ancestry = append(ancestry, fmt.Sprintf("depth:%d", file.ContainerDepth))
		}
	}
	return SubjectCacheIdentity{
		SourceType:             sourceType,
		SourceDigest:           sourceDigest,
		PhysicalPath:           physicalPath,
		VirtualArchiveAncestry: ancestry,
		MemberPath:             memberPath,
		ContentSHA256:          file.SHA256,
		AnalyzerID:             analyzerID,
		AnalyzerVersion:        analyzerVer,
		RulePackDigest:         ruleDigest,
		ConfigDigest:           configDigest,
		PolicyDigest:           policyDigest,
	}
}

// SubjectCoverageLedger tracks all 10 subject lifecycle states required by Phase 1.3.
type SubjectCoverageLedger struct {
	Requested     []string `json:"requested"`
	Discovered    []string `json:"discovered"`
	Loaded        []string `json:"loaded"`
	Analyzed      []string `json:"analyzed"`
	Verified      []string `json:"verified"`
	Excluded      []string `json:"excluded,omitempty"`
	Unsupported   []string `json:"unsupported,omitempty"`
	Failed        []string `json:"failed,omitempty"`
	BudgetLimited []string `json:"budget_limited,omitempty"`
	Unresolved    []string `json:"unresolved,omitempty"`
}

// Validate checks that every discovered or requested subject is accounted for
// and returns an error if any required subject was silently omitted or failed.
func (l SubjectCoverageLedger) Validate() error {
	if len(l.Requested) == 0 && len(l.Discovered) == 0 {
		return errors.New("subject coverage ledger has no requested or discovered subjects")
	}
	if len(l.Failed) > 0 {
		return fmt.Errorf("subject coverage incomplete: %d failed subjects", len(l.Failed))
	}
	if len(l.BudgetLimited) > 0 {
		return fmt.Errorf("subject coverage incomplete: %d budget-limited subjects", len(l.BudgetLimited))
	}
	if len(l.Unresolved) > 0 {
		return fmt.Errorf("subject coverage incomplete: %d unresolved subjects", len(l.Unresolved))
	}
	if len(l.Unsupported) > 0 {
		return fmt.Errorf("subject coverage incomplete: %d unsupported subjects", len(l.Unsupported))
	}
	accounted := map[string]bool{}
	for _, s := range l.Analyzed {
		accounted[s] = true
	}
	for _, s := range l.Excluded {
		accounted[s] = true
	}
	for _, s := range l.Discovered {
		if !accounted[s] {
			return fmt.Errorf("discovered subject %q was neither analyzed nor explicitly excluded by policy", s)
		}
	}
	for _, s := range l.Requested {
		if !accounted[s] {
			return fmt.Errorf("requested subject %q was neither analyzed nor explicitly excluded by policy", s)
		}
	}
	return nil
}

// ToCoverageUniverse converts the 10-state ledger into skil.CoverageUniverse
// and validates its completeness.
func (l SubjectCoverageLedger) ToCoverageUniverse() (skil.CoverageUniverse, error) {
	analyzedSet := map[string]bool{}
	for _, s := range l.Analyzed {
		analyzedSet[s] = true
	}
	excludedSet := map[string]bool{}
	for _, s := range l.Excluded {
		excludedSet[s] = true
	}
	unsupportedSet := map[string]bool{}
	for _, s := range l.Unsupported {
		unsupportedSet[s] = true
	}
	failedSet := map[string]bool{}
	for _, s := range l.Failed {
		failedSet[s] = true
	}
	budgetSet := map[string]bool{}
	for _, s := range l.BudgetLimited {
		budgetSet[s] = true
	}
	unresolvedSet := map[string]bool{}
	for _, s := range l.Unresolved {
		unresolvedSet[s] = true
	}

	all := map[string]bool{}
	for _, list := range [][]string{l.Requested, l.Discovered, l.Loaded, l.Analyzed, l.Verified, l.Excluded, l.Unsupported, l.Failed, l.BudgetLimited, l.Unresolved} {
		for _, s := range list {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				all[trimmed] = true
			}
		}
	}
	sortedIDs := make([]string, 0, len(all))
	for id := range all {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)

	var subjects []skil.CoverageSubject
	for _, id := range sortedIDs {
		disp := skil.CoverageOmitted
		switch {
		case failedSet[id]:
			disp = skil.CoverageFailed
		case budgetSet[id]:
			disp = skil.CoverageBudgetLimited
		case unsupportedSet[id]:
			disp = skil.CoverageUnsupported
		case unresolvedSet[id]:
			disp = skil.CoverageOmitted
		case excludedSet[id]:
			disp = skil.CoverageExcludedByPolicy
		case analyzedSet[id]:
			disp = skil.CoverageDiscovered
		}
		subjects = append(subjects, skil.CoverageSubject{
			ID:          id,
			Disposition: disp,
			Required:    !excludedSet[id],
		})
	}
	u := skil.CoverageUniverse{Subjects: subjects}
	if err := l.Validate(); err != nil {
		return u, err
	}
	if !u.Complete() {
		return u, errors.New("coverage universe is not complete")
	}
	return u, nil
}
