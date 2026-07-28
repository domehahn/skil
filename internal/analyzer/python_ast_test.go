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
	if counts["SKIL-PY-001"] != 0 || counts["SKIL-PY-002"] != 2 || counts["SKIL-PY-003"] != 1 || counts["SKIL-NET-001"] != 1 {
		t.Fatalf("%#v", findings)
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
