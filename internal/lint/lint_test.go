package lint

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestCleanUniversalSkillPasses(t *testing.T) {
	artifact := testArtifact(map[string]string{
		"skill.yaml": `name: reviewer
version: 1.2.3
description: Reviews documentation
entrypoint: SKILL.md
owners: [platform]
`,
		"SKILL.md": `---
name: reviewer
description: Reviews documentation
---
# Reviewer

Review the supplied documentation.
`,
	})
	result := Analyze(artifact, true)
	if result.Status != skil.StatusPass || len(result.Issues) != 0 {
		t.Fatalf("clean lint result = %#v", result)
	}
}

func TestLintFindsAuthoringAndCapabilityProblems(t *testing.T) {
	artifact := testArtifact(map[string]string{
		"skil.yaml": `version: 1
owner: platform
skill:
  name: broad-reviewer
  version: 1.0.0
  description: Reviews documentation
capabilities:
  filesystem:
    read: ["../outside", "**/*"]
    write: []
    delete: []
  network:
    inbound: false
    outbound: false
    hosts: []
  commands:
    execute: false
    allow: []
  secrets:
    read: []
    expose: false
  environment:
    read: []
  tools:
    allow: ["git.write"]
    deny: ["git.write"]
  mcp:
    servers: []
    tools: []
  persistence: false
  agent:
    autonomous_actions: false
    external_side_effects: false
    confirm_destructive: true
    confirm_external: true
`,
		"SKILL.md": `# Reviewer

See [missing](docs/missing.md).
TODO: finish this skill.
`,
		"package.json": `{broken`,
	})
	result := Analyze(artifact, false)
	for _, ruleID := range []string{
		"SKIL-LINT-FILESYSTEM-SCOPE",
		"SKIL-LINT-CAPABILITY-WILDCARD",
		"SKIL-LINT-TOOL-CONFLICT",
		"SKIL-LINT-FRONTMATTER-MISSING",
		"SKIL-LINT-LINK-BROKEN",
		"SKIL-LINT-PLACEHOLDER",
		"SKIL-LINT-JSON",
		"SKIL-LINT-LOCKFILE-MISSING",
	} {
		if !hasRule(result, ruleID) {
			t.Errorf("missing %s in %#v", ruleID, result.Issues)
		}
	}
	if result.Status != skil.StatusFail || result.Summary.Errors == 0 || result.Summary.Warnings == 0 {
		t.Fatalf("unexpected lint summary: %#v", result)
	}
}

func TestStrictModeGatesWarnings(t *testing.T) {
	artifact := testArtifact(map[string]string{
		"skill.yaml": `name: Reviewer
version: 1.0.0
description: Reviews documentation
entrypoint: SKILL.md
owners: [platform]
`,
		"SKILL.md": `---
name: Reviewer
description: Reviews documentation
---
# Reviewer
`,
	})
	regular := Analyze(artifact, false)
	strict := Analyze(artifact, true)
	if regular.Status != skil.StatusWarn || strict.Status != skil.StatusFail {
		t.Fatalf("regular=%s strict=%s", regular.Status, strict.Status)
	}
}

func TestAllLintFormats(t *testing.T) {
	result := Analyze(testArtifact(map[string]string{"SKILL.md": "# Incomplete\n"}), false)
	for _, format := range []string{"terminal", "json", "markdown", "sarif"} {
		var output bytes.Buffer
		if err := Write(&output, format, result); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if output.Len() == 0 {
			t.Fatalf("%s produced no output", format)
		}
		if format == "sarif" {
			var document map[string]any
			if err := json.Unmarshal(output.Bytes(), &document); err != nil {
				t.Fatalf("invalid SARIF: %v", err)
			}
		}
	}
	if err := Write(&bytes.Buffer{}, "xml", result); err == nil {
		t.Fatal("unsupported format accepted")
	}
}

func TestAdvancedOfflineAuthoringChecks(t *testing.T) {
	artifact := testArtifact(map[string]string{
		"skill.yaml": `name: advanced-fixture
version: 1.2.3
description: Advanced lint fixture
entrypoint: scripts/run.py
owners: [platform]
`,
		"SKILL.md": `---
name: advanced-fixture
description: Advanced lint fixture
---
# Repeated
# Repeated

[broken](#absent)

` + "```text\nunclosed\n",
		"scripts/run.py": `from .missing import helper
`,
		"package.json":      `{"dependencies":{"demo":"^1.2.3"}}`,
		"package-lock.json": `{}`,
		"yarn.lock":         "fixture",
		"mcp.json": `{
  "servers": {"duplicate": {}, "duplicate": {}},
  "tools": [
    {"name": "same", "inputSchema": "anything"},
    {"name": "same"}
  ]
}`,
		"first-eval.yaml": `version: 1
name: repeated-eval
type: adversarial
input: {message: test}
tools: {available: []}
expect: {}
`,
		"second-eval.yaml": `version: 1
name: repeated-eval
type: behavioral
input: {message: test}
tools: {available: []}
expect: {}
`,
		"NUL.txt":      "reserved",
		"result.sarif": "{}",
	})
	result := AnalyzeProfile(artifact, ProfileStrict)
	for _, ruleID := range []string{
		"SKIL-LINT-ANCHOR-BROKEN",
		"SKIL-LINT-ANCHOR-DUPLICATE",
		"SKIL-LINT-CODE-FENCE",
		"SKIL-LINT-DEPENDENCY-RANGE",
		"SKIL-LINT-ENTRYPOINT-MODE",
		"SKIL-LINT-EVAL-ASSERTIONS",
		"SKIL-LINT-EVAL-ATTACK",
		"SKIL-LINT-EVAL-NAME-DUPLICATE",
		"SKIL-LINT-FILENAME-PORTABILITY",
		"SKIL-LINT-IMPORT-BROKEN",
		"SKIL-LINT-JSON-DUPLICATE-KEY",
		"SKIL-LINT-LOCKFILE-CONFLICT",
		"SKIL-LINT-LOCKFILE-DRIFT",
		"SKIL-LINT-MCP-INPUT-SCHEMA",
		"SKIL-LINT-MCP-TOOL-DUPLICATE",
		"SKIL-LINT-MCP-UNDECLARED",
		"SKIL-LINT-SHEBANG-MISSING",
		"SKIL-LINT-TEMPORARY-FILE",
	} {
		if !hasRule(result, ruleID) {
			t.Errorf("missing %s in %#v", ruleID, result.Issues)
		}
	}
	if result.Status != skil.StatusFail || result.Profile != ProfileStrict {
		t.Fatalf("unexpected advanced lint result: %#v", result)
	}
}

func TestProfilesAndPublishReadiness(t *testing.T) {
	for _, profile := range []Profile{ProfileDefault, ProfileStrict, ProfilePortable, ProfilePublish} {
		parsed, err := ParseProfile(string(profile))
		if err != nil || parsed != profile {
			t.Fatalf("parse %s: %s %v", profile, parsed, err)
		}
	}
	if _, err := ParseProfile("unknown"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	artifact := testArtifact(map[string]string{
		"skill.yaml": `name: publish-fixture
version: 1.2.3
description: Publish fixture
entrypoint: SKILL.md
owners: [platform]
`,
		"SKILL.md": `---
name: publish-fixture
description: Publish fixture
---
# Publish fixture
`,
		"VERSION":      "1.2.3\n",
		"CHANGELOG.md": "# Changelog\n",
	})
	result := AnalyzeProfile(artifact, ProfilePublish)
	for _, ruleID := range []string{"SKIL-LINT-PACKAGE", "SKIL-LINT-LICENSE-MISSING", "SKIL-LINT-CHANGELOG-VERSION"} {
		if !hasRule(result, ruleID) {
			t.Errorf("publish profile missing %s: %#v", ruleID, result.Issues)
		}
	}
	if result.Status != skil.StatusFail || !result.Strict {
		t.Fatalf("unexpected publish result: %#v", result)
	}
}

func testArtifact(files map[string]string) skil.Artifact {
	artifact := skil.Artifact{Name: "lint-fixture", Source: ".", Digest: strings.Repeat("a", 64)}
	for path, data := range files {
		artifact.Files = append(artifact.Files, skil.File{Path: path, Data: []byte(data)})
	}
	return artifact
}

func hasRule(result Result, ruleID string) bool {
	for _, issue := range result.Issues {
		if issue.RuleID == ruleID {
			return true
		}
	}
	return false
}
