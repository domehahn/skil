package packagecheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestValidateRequiresAndVerifiesCanonicalPackage(t *testing.T) {
	a, b, c, d := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	files := []skil.File{
		{Path: "SKILL.md", SHA256: a},
		{Path: "VERSION", Data: []byte("1.2.3\n"), SHA256: b},
		{Path: "CHANGELOG.md", Data: []byte("# Changes\n"), SHA256: c},
		{Path: "skil.yaml", SHA256: d},
		{Path: "checksums.txt", Data: []byte(fmt.Sprintf(
			"%s  SKILL.md\n%s  VERSION\n%s  CHANGELOG.md\n%s  skil.yaml\n", a, b, c, d))},
	}
	result := Validate(skil.Artifact{Files: files}, skil.SkillContract{Skill: skil.SkillIdentity{Version: "1.2.3"}})
	if err := Error(result); err != nil {
		t.Fatal(err)
	}
	files[4].Data = []byte(strings.Repeat("f", 64) + "  SKILL.md\n")
	if err := Error(Validate(skil.Artifact{Files: files}, skil.SkillContract{Skill: skil.SkillIdentity{Version: "1.2.3"}})); err == nil {
		t.Fatal("expected checksum rejection")
	}
}
