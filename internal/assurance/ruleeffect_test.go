package assurance

import "testing"

func goodRule() VersionRule {
	return VersionRule{ID: "R1", Ecosystem: "semver", Constraint: ">=1.0.0,<1.2.3", Matcher: "pkg:npm/left-pad",
		Positive: []string{"1.0.0", "1.2.2"}, Negative: []string{"0.9.9", "1.2.3", "2.0.0"}}
}

func TestEffectiveRuleAcrossAllLevels(t *testing.T) {
	r := ValidateRule(goodRule(), nil)
	if !r.Effective() || r.RuleDigest == "" {
		t.Fatalf("%+v", r)
	}
}

func TestPreReleaseOrderingInRange(t *testing.T) {
	rule := goodRule()
	rule.Constraint = "<1.2.3"
	if EvaluateVersion(rule, "1.2.3-rc1") != VulnYes || EvaluateVersion(rule, "1.2.3") != VulnNo {
		t.Fatal("pre-release must sort below its release")
	}
}

func TestIneffectiveRulesAreDetected(t *testing.T) {
	cases := map[string]func(*VersionRule){
		"git hash as version": func(r *VersionRule) { r.Constraint = "<d41d8cd98f00b204e9800998ecf8427e" },
		"short git hash":      func(r *VersionRule) { r.Constraint = ">=a1b2c3d" },
		"empty constraint":    func(r *VersionRule) { r.Constraint = "" },
		"garbage version":     func(r *VersionRule) { r.Constraint = ">=latest" },
		"empty matcher":       func(r *VersionRule) { r.Matcher = "  " },
		"contradiction":       func(r *VersionRule) { r.Constraint = ">=2.0.0,<1.0.0" },
		"unsupported scheme":  func(r *VersionRule) { r.Ecosystem = "pep440" },
		"missing dependency":  func(r *VersionRule) { r.DependsOn = []string{"R-missing"} },
		"no negative fixture": func(r *VersionRule) { r.Negative = nil },
		"wrong positive":      func(r *VersionRule) { r.Positive = []string{"5.0.0"} },
		"wrong negative":      func(r *VersionRule) { r.Negative = []string{"1.1.0"} },
	}
	for name, mutate := range cases {
		rule := goodRule()
		mutate(&rule)
		if r := ValidateRule(rule, map[string]bool{}); r.Effective() || len(r.Issues) == 0 {
			t.Errorf("%s: rule judged effective: %+v", name, r)
		}
	}
}

func TestUnknownSemanticsNeverEvaluateToNotVulnerable(t *testing.T) {
	bad := []VersionRule{
		{Ecosystem: "pep440", Constraint: "<1.0.0"},
		{Ecosystem: "semver", Constraint: ""},
		{Ecosystem: "semver", Constraint: "<deadbeef"},
		{Ecosystem: "maven", Constraint: "<1.0.0"},
	}
	for _, r := range bad {
		if got := EvaluateVersion(r, "0.0.1"); got != VulnUnknown {
			t.Errorf("%+v -> %s", r, got)
		}
	}
	if EvaluateVersion(goodRule(), "not-a-version") != VulnUnknown {
		t.Fatal("unparseable candidate version must be UNKNOWN")
	}
}

func TestDigestChangesWithRuleContent(t *testing.T) {
	a := ValidateRule(goodRule(), nil)
	r := goodRule()
	r.Constraint = ">=1.0.0,<1.2.4"
	if a.RuleDigest == ValidateRule(r, nil).RuleDigest {
		t.Fatal("rule digest must bind rule content")
	}
}
