package analyzer

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// Build detects install-time/build-time hook mechanisms: npm lifecycle
// scripts, setuptools custom install commands, and remote
// download-and-execute patterns in build tooling files that skil's
// language-scoped analyzers don't cover (Makefile, build.rs, setup.py —
// code.go's shell-command rules are scoped to sh/bash/js/ts and skip these
// by design). Install-time behavior is a distinct trust boundary from
// runtime behavior: it executes merely by installing the dependency, before
// any of the skill's own code runs.
type Build struct{}

func NewBuild() *Build { return &Build{} }

func (b *Build) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.build", Version: "1.0.0",
		Domain: "supply-chain", Subdomain: "build",
		Categories:    []string{"build-supply-chain"},
		AnalysisTypes: []string{"build"}, SupportedTypes: []string{"json", "py", "text"}}
}

func (b *Build) Rules() []skil.Rule {
	return []skil.Rule{
		{ID: "SKIL-BUILD-INSTALL-HOOK", Title: "Install-time hook mechanism", Category: "build-supply-chain",
			Severity: skil.SeverityMedium, Analysis: "build",
			Description: "The artifact defines a hook that executes automatically at install time, before any of the skill's own code runs.",
			Remediation: "Review install-time hooks with the same scrutiny as runtime code; remove hooks that are not strictly necessary."},
		{ID: "SKIL-BUILD-REMOTE-EXEC", Title: "Remote download-and-execute at build/install time", Category: "build-supply-chain",
			Severity: skil.SeverityCritical, Analysis: "build",
			Description: "An install-time or build-time hook downloads and executes remote content.",
			Remediation: "Never download and execute remote content during install/build; vendor and review the dependency instead."},
	}
}

var (
	npmLifecycleHooks  = []string{"preinstall", "install", "postinstall", "prepare", "prepublish"}
	remoteExecPattern  = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|;&]{0,200}(?:\|\s*(?:ba)?sh\b|-o\s*\S+\s*&&\s*(?:ba)?sh\b)|(?:ba)?sh\s+-c\s+["'].{0,80}(?:curl|wget)|\bnode\s+-e\s+["'].{0,80}(?:https?://|require\(['"]child_process)|\bpython[23]?\s+-c\s+["'].{0,80}(?:urllib|requests|subprocess|os\.system)`)
	setupPyInstallHook = regexp.MustCompile(`(?i)cmdclass\s*=\s*\{[^}]*['"](?:install|develop|egg_info|build_py)['"]\s*:|class\s+\w+\(\s*(?:install|develop)\s*\)\s*:`)
	pipInstallHook     = regexp.MustCompile(`(?i)from\s+setuptools\s+import\s+setup|setup_requires\s*=\s*\[|pip\s+install\s+-e\s+\.`)
	gemspecBuildHook   = regexp.MustCompile(`(?i)spec\.(?:extensions|executables|require_paths)\s*=`)
	gradleBuildHook    = regexp.MustCompile(`(?i)(?:apply\s+plugin|plugins\s*\{)\s*(?:(?:['"])com\.android|application|['"]kotlin-android)|buildscript\s*\{|task\s+\w+\(type:\s*(?:Exec|Copy|Delete)`)
)

func (b *Build) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		base := baseName(file.Path)
		switch {
		case base == "package.json":
			out = append(out, b.scanPackageJSON(file)...)
		case base == "setup.py":
			out = append(out, b.scanSetupPy(file)...)
		case strings.HasPrefix(base, "Makefile") || base == "makefile":
			out = append(out, b.scanTextForRemoteExec(file)...)
		case base == "build.rs":
			out = append(out, b.scanTextForRemoteExec(file)...)
		case strings.HasSuffix(base, ".gemspec"):
			if gemspecBuildHook.Match(file.Data) {
				out = append(out, makeFinding(RulePattern{Rule: b.ruleByID("SKIL-BUILD-INSTALL-HOOK"), Confidence: .8},
					file, lineOf(file.Data, gemspecBuildHook), "gem extension/build hook"))
			}
		case base == "build.gradle" || base == "build.gradle.kts":
			if gradleBuildHook.Match(file.Data) {
				out = append(out, makeFinding(RulePattern{Rule: b.ruleByID("SKIL-BUILD-INSTALL-HOOK"), Confidence: .8},
					file, lineOf(file.Data, gradleBuildHook), "gradle build hook"))
			}
		case strings.HasSuffix(base, "requirements.txt") || strings.HasSuffix(base, "Pipfile") || strings.HasSuffix(base, "pyproject.toml"):
			if pipInstallHook.Match(file.Data) {
				out = append(out, makeFinding(RulePattern{Rule: b.ruleByID("SKIL-BUILD-INSTALL-HOOK"), Confidence: .75},
					file, lineOf(file.Data, pipInstallHook), "pip install hook reference"))
			}
		case strings.Contains(file.Path, ".husky/") && base != ".gitignore" && !strings.HasSuffix(base, ".md"):
			// Note: raw .git/hooks/ scripts are not checked here — the
			// artifact loader deliberately excludes the .git directory
			// entirely (VCS internals are never part of a distributed
			// skill artifact), so that path can never be reached through
			// a real scan and would be untestable dead code.
			out = append(out, makeFinding(RulePattern{Rule: b.ruleByID("SKIL-BUILD-INSTALL-HOOK"), Confidence: .85},
				file, 1, "husky git hook: "+base))
		}
	}
	return out, nil
}

func (b *Build) ruleByID(id string) skil.Rule {
	for _, r := range b.Rules() {
		if r.ID == id {
			return r
		}
	}
	return skil.Rule{ID: id}
}

func (b *Build) scanPackageJSON(file skil.File) []skil.Finding {
	var doc struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(file.Data, &doc) != nil || len(doc.Scripts) == 0 {
		return nil
	}
	var out []skil.Finding
	for _, hook := range npmLifecycleHooks {
		command, ok := doc.Scripts[hook]
		if !ok || strings.TrimSpace(command) == "" {
			continue
		}
		line, text := lineContaining(file.Data, command)
		if remoteExecPattern.MatchString(command) {
			finding := makeFinding(RulePattern{Rule: b.ruleByID("SKIL-BUILD-REMOTE-EXEC"), Confidence: .95}, file, line, text)
			finding.Evidence["hook"] = hook
			out = append(out, finding)
			continue
		}
		finding := makeFinding(RulePattern{Rule: b.ruleByID("SKIL-BUILD-INSTALL-HOOK"), Confidence: .8}, file, line, text)
		finding.Evidence["hook"] = hook
		out = append(out, finding)
	}
	return out
}

func (b *Build) scanSetupPy(file skil.File) []skil.Finding {
	var out []skil.Finding
	if remoteExecPattern.Match(file.Data) {
		out = append(out, makeFinding(RulePattern{Rule: b.ruleByID("SKIL-BUILD-REMOTE-EXEC"), Confidence: .9},
			file, lineOf(file.Data, remoteExecPattern), "remote download-and-execute in setup.py"))
	}
	if setupPyInstallHook.Match(file.Data) {
		out = append(out, makeFinding(RulePattern{Rule: b.ruleByID("SKIL-BUILD-INSTALL-HOOK"), Confidence: .85},
			file, lineOf(file.Data, setupPyInstallHook), "custom setuptools install command override"))
	}
	return out
}

func (b *Build) scanTextForRemoteExec(file skil.File) []skil.Finding {
	if !remoteExecPattern.Match(file.Data) {
		return nil
	}
	return []skil.Finding{makeFinding(RulePattern{Rule: b.ruleByID("SKIL-BUILD-REMOTE-EXEC"), Confidence: .9},
		file, lineOf(file.Data, remoteExecPattern), "remote download-and-execute at build time")}
}
