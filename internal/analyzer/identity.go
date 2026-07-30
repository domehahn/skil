package analyzer

import (
	"context"
	"regexp"

	"github.com/domehahn/skil/pkg/skil"
)

// Identity detects agent/service identity misuse patterns distinct from
// plain capability or secret checks: a tool call can be entirely
// legitimate while the *identity* behind it is far too powerful (an
// assumable role trusted by anyone, a forwarded end-user credential reused
// against a different downstream service, or explicit identity
// impersonation).
type Identity struct{ rules []RulePattern }

func NewIdentity() *Identity {
	rule := func(id, title, category string, severity skil.Severity, expression, description, remediation string) RulePattern {
		return RulePattern{Rule: skil.Rule{
			ID: id, Title: title, Category: category, Severity: severity,
			Description: description, Analysis: "identity", AppliesTo: []string{"text", "code"},
			Remediation: remediation,
		}, Pattern: regexp.MustCompile("(?i)" + expression), Confidence: .9}
	}
	return &Identity{rules: []RulePattern{
		rule("SKIL-ID-ROLE-ASSUMPTION", "Trust policy assumable by any principal", "identity-security", skil.SeverityCritical,
			`"?Principal"?\s*[:=]\s*"?\*"?|AssumeRolePolicyDocument.{0,200}"Principal"\s*:\s*"\*"`,
			"An IAM trust or role-assumption policy trusts any principal (\"*\") rather than a named, reviewed identity.",
			"Scope the trust policy's Principal to exact, named accounts or roles."),
		rule("SKIL-ID-TOKEN-FORWARDING", "Incoming credential forwarded to a downstream call", "identity-security", skil.SeverityHigh,
			`headers\s*=\s*(?:dict\()?\s*(?:\*\*)?request\.headers\b|headers\[['"]authorization['"]\]\s*=\s*request\.headers|proxy_headers\s*=\s*request\.headers`,
			"An incoming request's headers (potentially including its Authorization credential) are forwarded wholesale to a downstream call.",
			"Forward only the specific headers a downstream call legitimately needs; never pass an incoming credential through to an unrelated service."),
		rule("SKIL-ID-IMPERSONATION", "Explicit identity impersonation", "identity-security", skil.SeverityHigh,
			`--impersonate-service-account\b|kubectl\s+[^\n]{0,80}--as(?:-group)?[= ]|\bsudo\s+-u\s+\S+`,
			"Content explicitly impersonates a different service account, Kubernetes identity, or local user.",
			"Remove identity impersonation or require it to go through an explicit, audited, narrowly-scoped delegation mechanism."),
		rule("SKIL-ID-LONG-LIVED-TOKEN", "Long-lived static credential reference", "identity-security", skil.SeverityHigh,
			`serviceAccountToken|static[_-]?credential|long[_-]?lived[_-]?token|permanent[_-]?(?:api[_-]?key|token)|never[_-]?expir`,
			"A reference to a long-lived or non-expiring static credential, which increases the blast radius of any credential leak.",
			"Replace long-lived static credentials with short-lived, auto-rotating tokens (OIDC, STS, workload identity)."),
		rule("SKIL-ID-BROAD-SCOPE", "Excessively broad scope/role definition", "identity-security", skil.SeverityHigh,
			`(?:Action|Actions)\s*:\s*\[?\s*['"]\*(['"])|Effect\s*:\s*Allow.*Resource\s*:\s*\*|"Effect"\s*:\s*"Allow".{0,200}"Resource"\s*:\s*"\*"`,
			"An IAM policy, RBAC role, or permission scope grants all actions or all resources — far more access than any single principal needs.",
			"Scope actions and resources to the minimum required for the principal's function; avoid wildcards."),
	}}
}

func (id *Identity) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.identity", Version: "1.0.0",
		Domain: "identity-auth", Subdomain: "excessive-scope",
		Categories:    []string{"identity-security"},
		AnalysisTypes: []string{"identity"}, SupportedTypes: []string{"text"}}
}

func (id *Identity) Rules() []skil.Rule {
	out := make([]skil.Rule, len(id.rules))
	for i := range id.rules {
		out[i] = id.rules[i].Rule
	}
	return out
}

func (id *Identity) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if !isText(file) {
			continue
		}
		for lineNumber, text := range lines(file.Data) {
			for _, control := range id.rules {
				if control.Pattern.MatchString(text) {
					out = append(out, makeFinding(control, file, lineNumber+1, text))
				}
			}
		}
	}
	return out, nil
}
