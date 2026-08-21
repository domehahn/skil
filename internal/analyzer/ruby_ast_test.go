package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func rubyContext(path, content string) skil.AnalysisContext {
	return skil.AnalysisContext{Artifact: artifactWith(path, content)}
}

func ruleCount(findings []skil.Finding, rule string) int {
	count := 0
	for _, finding := range findings {
		if finding.RuleID == rule {
			count++
		}
	}
	return count
}

func TestRubyASTDetectsDynamicExecution(t *testing.T) {
	findings, err := NewRubyAST().Analyze(context.Background(), rubyContext("script.rb", `
eval(user_input)
instance_eval(payload)
`))
	if err != nil {
		t.Fatal(err)
	}
	if count := ruleCount(findings, "SKIL-RB-001"); count != 2 {
		t.Fatalf("expected 2 SKIL-RB-001 findings, got %d: %#v", count, findings)
	}
}

func TestRubyASTDetectsProcessExecution(t *testing.T) {
	cases := []string{
		`system("rm -rf /")`,
		"`ls -la`",
		"%x{ls -la}",
		`IO.popen("ls")`,
		`Open3.capture2("ls")`,
		`Kernel.exec("ls")`,
	}
	for _, source := range cases {
		findings, err := NewRubyAST().Analyze(context.Background(), rubyContext("script.rb", source))
		if err != nil {
			t.Fatal(err)
		}
		if !hasRule(findings, "SKIL-RB-002") {
			t.Fatalf("expected SKIL-RB-002 for %q, got %#v", source, findings)
		}
	}
}

func TestRubyASTDetectsUnsafeDeserialization(t *testing.T) {
	cases := []string{`Marshal.load(data)`, `YAML.load(data)`, `Psych.load(data)`}
	for _, source := range cases {
		findings, err := NewRubyAST().Analyze(context.Background(), rubyContext("script.rb", source))
		if err != nil {
			t.Fatal(err)
		}
		if !hasRule(findings, "SKIL-RB-003") {
			t.Fatalf("expected SKIL-RB-003 for %q, got %#v", source, findings)
		}
	}
}

func TestRubyASTDetectsReflectiveDispatchOnlyWhenDynamic(t *testing.T) {
	findings, err := NewRubyAST().Analyze(context.Background(), rubyContext("script.rb", `
send(method_name, arg)
send(:literal_method, arg)
__send__(dynamic_var)
`))
	if err != nil {
		t.Fatal(err)
	}
	if count := ruleCount(findings, "SKIL-RB-004"); count != 2 {
		t.Fatalf("expected 2 SKIL-RB-004 findings (dynamic dispatch only, not the literal-symbol one), got %d: %#v", count, findings)
	}
}

func TestRubyASTDetectsNetworkAndSecretAccess(t *testing.T) {
	findings, observations, err := NewRubyAST().AnalyzeCapabilities(context.Background(), rubyContext("script.rb", `
Net::HTTP.get(uri)
URI.open("https://example.com")
ENV["API_KEY"]
ENV.fetch("API_KEY")
`))
	if err != nil {
		t.Fatal(err)
	}
	if count := ruleCount(findings, "SKIL-NET-001"); count != 2 {
		t.Fatalf("expected 2 SKIL-NET-001 findings, got %d: %#v", count, findings)
	}
	if count := ruleCount(findings, "SKIL-SEC-001"); count != 2 {
		t.Fatalf("expected 2 SKIL-SEC-001 findings, got %d: %#v", count, findings)
	}
	var haveSecretsRead, haveEnvironmentRead, haveNetworkOutbound bool
	for _, observation := range observations {
		switch observation.Capability {
		case "secrets.read":
			haveSecretsRead = true
		case "environment.read":
			haveEnvironmentRead = true
		case "network.outbound":
			haveNetworkOutbound = true
		}
	}
	if !haveSecretsRead || !haveEnvironmentRead || !haveNetworkOutbound {
		t.Fatalf("expected secrets.read, environment.read, and network.outbound observations, got %#v", observations)
	}
}

func TestRubyASTCleanFileProducesNoFindings(t *testing.T) {
	findings, err := NewRubyAST().Analyze(context.Background(), rubyContext("script.rb", `
def greet(name)
  puts "Hello, #{name}!"
end

greet("world")
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings from ordinary Ruby code, got %#v", findings)
	}
}

func TestRubyASTIgnoresNonRubyFiles(t *testing.T) {
	findings, err := NewRubyAST().Analyze(context.Background(), rubyContext("script.py", `eval(x)`))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected RubyAST to ignore a .py file, got %#v", findings)
	}
}

func TestRubyASTRulesAreRegisteredInBuiltinCatalog(t *testing.T) {
	catalog := map[string]bool{}
	for _, rule := range BuiltinRules() {
		catalog[rule.ID] = true
	}
	for _, id := range []string{"SKIL-RB-001", "SKIL-RB-002", "SKIL-RB-003", "SKIL-RB-004"} {
		if !catalog[id] {
			t.Fatalf("expected %s to be in BuiltinRules()", id)
		}
	}
}
