package analyzer

import (
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

// CredentialFlow covers ASP-04 (Identity & Authorization) properties that
// Identity does not: audience binding on token verification, overbroad OAuth
// scope requests, non-expiring token issuance, and a delegated credential's
// requested scope exceeding the scope the resource owner actually consented
// to. The first three are line-local code patterns handled the same way as
// Identity; consent scope is a structural property of a consent/grant
// manifest (any YAML/JSON document declaring both a consent_scope and a
// requested_scope) and needs the same subset check multi_agent.go uses for
// delegation-scope escalation, applied to consent instead of delegation.
var (
	tokenVerificationCall = regexp.MustCompile(`(?i)\b(?:jwt\.decode|verify_token|verify_jwt)\s*\(`)
	audienceKeyword       = regexp.MustCompile(`(?i)\baud(?:ience)?\b`)
	explicitAudienceOff   = regexp.MustCompile(`(?i)\bverify_aud\s*=\s*False\b`)
)

func audienceBindingMissingRule() RulePattern {
	return RulePattern{Rule: skil.Rule{
		ID: "SKIL-AUTH-AUDIENCE", Title: "Token verification without audience binding",
		Category: "identity-security", Severity: skil.SeverityHigh,
		Description: "A token is verified without checking its audience (aud) claim, so a token issued for one service can be replayed against another.",
		Analysis:    "credential-flow", Remediation: "Always verify the token's audience claim matches this service's own resource identifier before accepting it.",
	}, Confidence: .85}
}

type CredentialFlow struct{ rules []RulePattern }

func NewCredentialFlow() *CredentialFlow {
	rule := func(id, title string, severity skil.Severity, expression, description, remediation string) RulePattern {
		return RulePattern{Rule: skil.Rule{
			ID: id, Title: title, Category: "identity-security", Severity: severity,
			Description: description, Analysis: "credential-flow", AppliesTo: []string{"text", "code"},
			Remediation: remediation,
		}, Pattern: regexp.MustCompile("(?i)" + expression), Confidence: .9}
	}
	return &CredentialFlow{rules: []RulePattern{
		rule("SKIL-AUTH-SCOPE-OVERBROAD", "Overbroad OAuth scope request", skil.SeverityHigh,
			`\bscopes?\s*[:=]\s*\[?\s*["'](?:\*|all|admin|full[_-]?access|superuser)["']`,
			"An OAuth/token request asks for a wildcard or administrative scope rather than the minimum scope the operation needs.",
			"Request the narrowest OAuth scope that satisfies the operation; never request wildcard or admin scope."),
		rule("SKIL-AUTH-LIFETIME", "Excessive or non-expiring token lifetime", skil.SeverityHigh,
			`\b(?:no[_-]?expir\w*\s*=\s*True|never[_-]?expir\w*\s*=\s*True|expires?_in\s*[:=]\s*0\b|expires?_in\s*[:=]\s*9{6,}|ttl\s*[:=]\s*-1\b)`,
			"A token or credential is issued with no expiration or an unreasonably long lifetime, increasing the blast radius of any leak.",
			"Issue short-lived tokens with an explicit TTL appropriate to the operation, and rotate or re-mint rather than extend lifetime."),
	}}
}

func (c *CredentialFlow) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{ID: "builtin.credential-flow", Version: "1.0.0",
		Domain: "identity-auth", Subdomain: "token-forwarding",
		Categories:    []string{"identity-security"},
		AnalysisTypes: []string{"credential-flow"}, SupportedTypes: []string{"*"}}
}

func (c *CredentialFlow) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		if isText(file) {
			for lineNumber, text := range lines(file.Data) {
				for _, control := range c.rules {
					if control.Pattern.MatchString(text) {
						out = append(out, makeFinding(control, file, lineNumber+1, text))
					}
				}
				if explicitAudienceOff.MatchString(text) ||
					(tokenVerificationCall.MatchString(text) && !audienceKeyword.MatchString(text)) {
					out = append(out, makeFinding(audienceBindingMissingRule(), file, lineNumber+1, text))
				}
			}
		}
		if !strings.Contains(string(file.Data), "consent_scope") {
			continue
		}
		var document any
		if err := yaml.Unmarshal(file.Data, &document); err != nil || !isStructuredMCPDocument(document) {
			continue
		}
		for _, excess := range consentScopeExcess(document) {
			line, text := lineContaining(file.Data, "requested_scope")
			out = append(out, makeFinding(RulePattern{Rule: skil.Rule{
				ID: "SKIL-AUTH-CONSENT-SCOPE", Title: "Consent scope exceeded",
				Category: "identity-security", Severity: skil.SeverityCritical,
				Description: "The requested scope includes [" + strings.Join(excess, ", ") + "], which the resource owner's consent_scope does not grant.",
				Analysis:    "credential-flow", Remediation: "Request only scope the resource owner has actually consented to; re-request consent before widening scope.",
			}, Confidence: .95}, file, line, text))
		}
	}
	return out, nil
}

// consentScopeExcess returns the requested_scope entries not present in
// consent_scope for any document declaring both lists at the same level,
// e.g. {consent_scope: [read], requested_scope: [read, write]}.
func consentScopeExcess(value any) [][]string {
	var out [][]string
	var visit func(any)
	visit = func(v any) {
		switch item := v.(type) {
		case map[string]any:
			consent := mcpStringSlice(item["consent_scope"])
			requested := mcpStringSlice(item["requested_scope"])
			if len(consent) > 0 && len(requested) > 0 {
				granted := map[string]bool{}
				for _, s := range consent {
					granted[s] = true
				}
				var extra []string
				for _, s := range requested {
					if !granted[s] {
						extra = append(extra, s)
					}
				}
				if len(extra) > 0 {
					out = append(out, sortedStrings(extra))
				}
			}
			for _, key := range sortedMapKeys(item) {
				visit(item[key])
			}
		case []any:
			for _, child := range item {
				visit(child)
			}
		}
	}
	visit(value)
	return out
}
