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
