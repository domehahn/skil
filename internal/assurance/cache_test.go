package assurance

import (
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestBuildCacheKeyPreventsCrossSubjectContamination(t *testing.T) {
	art := skil.Artifact{
		Name:   "bundle",
		Digest: "sha256:rootdigest",
	}
	physical := skil.File{
		Path:   "scripts/run.py",
		SHA256: "deadbeef",
	}
	virtual := skil.File{
		Path:                  "nested.zip!/scripts/run.py",
		SHA256:                "deadbeef", // identical content bytes
		ContainerDepth:        1,
		ContainerParentSHA256: "parentzipsha",
	}

	idPhys := SubjectIdentityForFile(art, physical, "builtin.python-ast", "1.0.0", "rules-v1", "cfg-v1", "pol-v1")
	idVirt := SubjectIdentityForFile(art, virtual, "builtin.python-ast", "1.0.0", "rules-v1", "cfg-v1", "pol-v1")

	keyPhys, err := BuildCacheKey(idPhys)
	if err != nil {
		t.Fatalf("unexpected error for physical file: %v", err)
	}
	keyVirt, err := BuildCacheKey(idVirt)
	if err != nil {
		t.Fatalf("unexpected error for virtual file: %v", err)
	}
	if keyPhys == keyVirt {
		t.Fatalf("physical file and virtual archive member with identical content must not share cache key: %s", keyPhys)
	}

	// Changing policy or rule digest must invalidate cache key.
	idPolChanged := idPhys
	idPolChanged.PolicyDigest = "pol-v2"
	keyPol2, err := BuildCacheKey(idPolChanged)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keyPhys == keyPol2 {
		t.Fatal("policy digest change must produce a distinct cache key")
	}

	// Missing required identity dimension must fail closed.
	invalid := idPhys
	invalid.RulePackDigest = ""
	if _, err := BuildCacheKey(invalid); err == nil {
		t.Fatal("expected error when rule_pack_digest is empty")
	}
}

func TestSubjectCoverageLedgerValidation(t *testing.T) {
	complete := SubjectCoverageLedger{
		Requested:  []string{"SKILL.md", "run.py"},
		Discovered: []string{"SKILL.md", "run.py", "ignored.txt"},
		Loaded:     []string{"SKILL.md", "run.py"},
		Analyzed:   []string{"SKILL.md", "run.py"},
		Verified:   []string{"SKILL.md", "run.py"},
		Excluded:   []string{"ignored.txt"},
	}
	u, err := complete.ToCoverageUniverse()
	if err != nil || !u.Complete() {
		t.Fatalf("expected complete coverage universe, got complete=%v err=%v", u.Complete(), err)
	}

	omitted := complete
	omitted.Analyzed = []string{"SKILL.md"} // run.py silently omitted
	if _, err := omitted.ToCoverageUniverse(); err == nil {
		t.Fatal("expected error when discovered subject is neither analyzed nor excluded")
	}
}
