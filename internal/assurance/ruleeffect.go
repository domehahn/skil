package assurance

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/domehahn/skil/internal/versioning"
	"github.com/domehahn/skil/pkg/skil"
)

// VulnState is a tri-state: an advisory rule that cannot be evaluated is
// UNKNOWN, never NOT_VULNERABLE.
type VulnState string

const (
	VulnYes     VulnState = "VULNERABLE"
	VulnNo      VulnState = "NOT_VULNERABLE"
	VulnUnknown VulnState = "UNKNOWN"
)

// VersionRule is a version-range advisory rule.
type VersionRule struct {
	ID         string   `json:"id"`
	Ecosystem  string   `json:"ecosystem"`
	Constraint string   `json:"constraint"` // e.g. ">=1.0.0,<1.2.3"
	Matcher    string   `json:"matcher"`    // package/product identifier
	DependsOn  []string `json:"depends_on,omitempty"`
	Positive   []string `json:"positive_fixtures"`
	Negative   []string `json:"negative_fixtures"`
}

// RuleEffectiveness distinguishes the five levels from the mission: loaded,
// syntactically valid, semantically valid, executable, behavior verified.
type RuleEffectiveness struct {
	RuleID           string   `json:"rule_id"`
	RuleDigest       string   `json:"rule_digest"`
	Loaded           bool     `json:"loaded"`
	SyntacticallyOK  bool     `json:"syntactically_valid"`
	SemanticallyOK   bool     `json:"semantically_valid"`
	Executable       bool     `json:"executable"`
	BehaviorVerified bool     `json:"behavior_verified"`
	Issues           []string `json:"issues,omitempty"`
}

// Effective is true only when every level holds.
func (r RuleEffectiveness) Effective() bool {
	return r.Loaded && r.SyntacticallyOK && r.SemanticallyOK && r.Executable && r.BehaviorVerified
}

var (
	strictSemver = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$`)
	gitHashLike  = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
	clauseRe     = regexp.MustCompile(`^(<=|>=|<|>|=)?\s*(\S+)$`)
)

// supportedEcosystem reports ecosystems whose ordering this package implements
// strictly. Anything else is UNKNOWN rather than evaluated with a guess.
func supportedEcosystem(e string) (versioning.Ecosystem, bool) {
	switch strings.ToLower(e) {
	case "semver":
		return versioning.EcosystemSemVer, true
	case "npm":
		return versioning.EcosystemNPM, true
	case "cargo":
		return versioning.EcosystemCargo, true
	}
	return "", false
}

type clause struct{ op, version string }

func parseConstraint(expr string) ([]clause, []string) {
	var issues []string
	var out []clause
	if strings.TrimSpace(expr) == "" {
		return nil, []string{"empty version constraint matches nothing"}
	}
	for _, raw := range strings.Split(expr, ",") {
		m := clauseRe.FindStringSubmatch(strings.TrimSpace(raw))
		if m == nil {
			issues = append(issues, fmt.Sprintf("unparseable clause %q", raw))
			continue
		}
		op, v := m[1], m[2]
		if op == "" {
			op = "="
		}
		switch {
		case gitHashLike.MatchString(v) && !strings.Contains(v, "."):
			issues = append(issues, fmt.Sprintf("clause %q uses a git hash as a version", raw))
		case !strictSemver.MatchString(v):
			issues = append(issues, fmt.Sprintf("clause %q is not a valid version for a semver-ordered ecosystem", raw))
		default:
			out = append(out, clause{op, v})
		}
	}
	return out, issues
}

// EvaluateVersion decides whether version falls inside the rule's range. It
// returns VulnUnknown (never VulnNo) when the rule or the version cannot be
// evaluated.
func EvaluateVersion(rule VersionRule, version string) VulnState {
	eco, ok := supportedEcosystem(rule.Ecosystem)
	if !ok {
		return VulnUnknown
	}
	clauses, issues := parseConstraint(rule.Constraint)
	if len(issues) > 0 || len(clauses) == 0 || !strictSemver.MatchString(strings.TrimSpace(version)) {
		return VulnUnknown
	}
	if contradictory(clauses, rule.Ecosystem) {
		return VulnUnknown
	}
	return evaluateClauses(eco, clauses, version)
}

func evaluateClauses(eco versioning.Ecosystem, clauses []clause, version string) VulnState {
	for _, c := range clauses {
		cmp, err := versioning.CompareEcosystemVersions(eco, strings.TrimSpace(version), c.version)
		if err != nil {
			return VulnUnknown
		}
		ok := false
		switch c.op {
		case "<":
			ok = cmp < 0
		case "<=":
			ok = cmp <= 0
		case ">":
			ok = cmp > 0
		case ">=":
			ok = cmp >= 0
		case "=":
			ok = cmp == 0
		}
		if !ok {
			return VulnNo
		}
	}
	return VulnYes
}

// ValidateRule runs all five effectiveness levels. known lists rule IDs that
// exist, for dependency resolution.
func ValidateRule(rule VersionRule, known map[string]bool) RuleEffectiveness {
	res := RuleEffectiveness{RuleID: rule.ID, RuleDigest: skil.DigestJSON(rule), Loaded: rule.ID != ""}
	if !res.Loaded {
		res.Issues = append(res.Issues, "rule has no identity")
		return res
	}
	if strings.TrimSpace(rule.Matcher) == "" {
		res.Issues = append(res.Issues, "empty matcher")
	}
	clauses, issues := parseConstraint(rule.Constraint)
	res.Issues = append(res.Issues, issues...)
	res.SyntacticallyOK = strings.TrimSpace(rule.Matcher) != "" && len(issues) == 0 && len(clauses) > 0

	_, eco := supportedEcosystem(rule.Ecosystem)
	if !eco {
		res.Issues = append(res.Issues, fmt.Sprintf("unsupported version scheme %q", rule.Ecosystem))
	}
	for _, dep := range rule.DependsOn {
		if !known[dep] {
			res.Issues = append(res.Issues, fmt.Sprintf("missing rule dependency %q", dep))
		}
	}
	contradiction := res.SyntacticallyOK && eco && contradictory(clauses, rule.Ecosystem)
	if contradiction {
		res.Issues = append(res.Issues, "contradictory conditions: no version can satisfy all clauses")
	}
	missingDeps := false
	for _, dep := range rule.DependsOn {
		if !known[dep] {
			missingDeps = true
		}
	}
	res.SemanticallyOK = res.SyntacticallyOK && eco && !contradiction && !missingDeps
	res.Executable = res.SemanticallyOK

	if res.Executable {
		ok := len(rule.Positive) > 0 && len(rule.Negative) > 0
		if !ok {
			res.Issues = append(res.Issues, "rule requires at least one positive and one negative fixture")
		}
		for _, v := range rule.Positive {
			if EvaluateVersion(rule, v) != VulnYes {
				ok = false
				res.Issues = append(res.Issues, fmt.Sprintf("positive fixture %q was not matched", v))
			}
		}
		for _, v := range rule.Negative {
			if EvaluateVersion(rule, v) != VulnNo {
				ok = false
				res.Issues = append(res.Issues, fmt.Sprintf("negative fixture %q was not rejected", v))
			}
		}
		res.BehaviorVerified = ok
	}
	sort.Strings(res.Issues)
	return res
}

// contradictory probes the boundary versions named in the clauses plus their
// neighbours; if none satisfies every clause the range is empty.
func contradictory(clauses []clause, ecosystem string) bool {
	probe := map[string]bool{}
	for _, c := range clauses {
		v := strings.TrimPrefix(c.version, "v")
		probe[v] = true
		parts := strings.SplitN(strings.SplitN(v, "-", 2)[0], ".", 3)
		if len(parts) == 3 {
			var a, b, p int
			fmt.Sscanf(strings.Join(parts, " "), "%d %d %d", &a, &b, &p)
			probe[fmt.Sprintf("%d.%d.%d", a, b, p+1)] = true
			if p > 0 {
				probe[fmt.Sprintf("%d.%d.%d", a, b, p-1)] = true
			}
			probe[fmt.Sprintf("%d.%d.0", a, b+1)] = true
		}
	}
	eco, ok := supportedEcosystem(ecosystem)
	if !ok {
		return false
	}
	for v := range probe {
		if evaluateClauses(eco, clauses, v) == VulnYes {
			return false
		}
	}
	return true
}

func joinClauses(cs []clause) string {
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = c.op + c.version
	}
	return strings.Join(parts, ",")
}
