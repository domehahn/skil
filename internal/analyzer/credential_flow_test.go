package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func credentialFlowFindings(t *testing.T, path, content string) []skil.Finding {
	t.Helper()
	findings, err := NewCredentialFlow().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith(path, content)})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestTokenVerificationWithoutAudienceIsDetected(t *testing.T) {
	content := "claims = jwt.decode(token, key, algorithms=['RS256'])\n"
	findings := credentialFlowFindings(t, "auth.py", content)
	if !hasRule(findings, "SKIL-AUTH-AUDIENCE") {
		t.Fatalf("expected token verification without audience binding to be detected: %#v", findings)
	}
}

func TestTokenVerificationWithAudienceIsSafe(t *testing.T) {
	content := "claims = jwt.decode(token, key, algorithms=['RS256'], audience='https://api.example.com')\n"
	findings := credentialFlowFindings(t, "auth.py", content)
	if hasRule(findings, "SKIL-AUTH-AUDIENCE") {
		t.Fatalf("token verification with an audience check should not fire: %#v", findings)
	}
}

func TestWildcardOAuthScopeIsDetected(t *testing.T) {
	content := `scope = "*"` + "\n"
	findings := credentialFlowFindings(t, "auth.py", content)
	if !hasRule(findings, "SKIL-AUTH-SCOPE-OVERBROAD") {
		t.Fatalf("expected a wildcard OAuth scope request to be detected: %#v", findings)
	}
}

func TestNarrowOAuthScopeIsSafe(t *testing.T) {
	content := `scope = "repo:read"` + "\n"
	findings := credentialFlowFindings(t, "auth.py", content)
	if hasRule(findings, "SKIL-AUTH-SCOPE-OVERBROAD") {
		t.Fatalf("a narrowly scoped OAuth request should not fire: %#v", findings)
	}
}

func TestNonExpiringTokenIsDetected(t *testing.T) {
	content := "issue_token(subject, never_expire=True)\n"
	findings := credentialFlowFindings(t, "auth.py", content)
	if !hasRule(findings, "SKIL-AUTH-LIFETIME") {
		t.Fatalf("expected a non-expiring token to be detected: %#v", findings)
	}
}

func TestShortLivedTokenIssuanceIsSafe(t *testing.T) {
	content := "issue_token(subject, expires_in=300)\n"
	findings := credentialFlowFindings(t, "auth.py", content)
	if hasRule(findings, "SKIL-AUTH-LIFETIME") {
		t.Fatalf("a short-lived token issuance should not fire: %#v", findings)
	}
}

func TestConsentScopeExceededIsDetected(t *testing.T) {
	content := "consent_scope: [read_repo]\nrequested_scope: [read_repo, write_repo]\n"
	findings := credentialFlowFindings(t, "grant.yaml", content)
	if !hasRule(findings, "SKIL-AUTH-CONSENT-SCOPE") {
		t.Fatalf("expected a requested scope beyond consent to be detected: %#v", findings)
	}
}

func TestConsentScopeContainedIsSafe(t *testing.T) {
	content := "consent_scope: [read_repo, write_repo]\nrequested_scope: [read_repo]\n"
	findings := credentialFlowFindings(t, "grant.yaml", content)
	if hasRule(findings, "SKIL-AUTH-CONSENT-SCOPE") {
		t.Fatalf("a requested scope within consent should not fire: %#v", findings)
	}
}
