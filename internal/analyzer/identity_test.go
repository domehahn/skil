package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func identityFindings(t *testing.T, path, content string) []skil.Finding {
	t.Helper()
	findings, err := NewIdentity().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith(path, content)})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestBroadTrustPolicyIsDetected(t *testing.T) {
	content := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}` + "\n"
	findings := identityFindings(t, "trust.json", content)
	if !hasRule(findings, "SKIL-ID-ROLE-ASSUMPTION") {
		t.Fatalf("expected a wildcard-principal trust policy to be detected: %#v", findings)
	}
}

func TestNamedPrincipalTrustPolicyIsSafe(t *testing.T) {
	content := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/ci-deployer"},"Action":"sts:AssumeRole"}]}` + "\n"
	findings := identityFindings(t, "trust.json", content)
	if hasRule(findings, "SKIL-ID-ROLE-ASSUMPTION") {
		t.Fatalf("a trust policy naming a specific role should not fire: %#v", findings)
	}
}

func TestIncomingHeadersForwardedDownstreamIsDetected(t *testing.T) {
	content := "headers = request.headers\nresp = requests.get(url, headers=headers)\n"
	findings := identityFindings(t, "proxy.py", content)
	if !hasRule(findings, "SKIL-ID-TOKEN-FORWARDING") {
		t.Fatalf("expected wholesale header forwarding to be detected: %#v", findings)
	}
}

func TestExplicitScopedHeadersAreSafe(t *testing.T) {
	content := `resp = requests.get(url, headers={"Content-Type": "application/json"})` + "\n"
	findings := identityFindings(t, "proxy.py", content)
	if hasRule(findings, "SKIL-ID-TOKEN-FORWARDING") {
		t.Fatalf("explicitly scoped headers should not fire: %#v", findings)
	}
}

func TestServiceAccountImpersonationIsDetected(t *testing.T) {
	content := "gcloud compute ssh myinstance --impersonate-service-account=admin@project.iam.gserviceaccount.com\n"
	findings := identityFindings(t, "deploy.sh", content)
	if !hasRule(findings, "SKIL-ID-IMPERSONATION") {
		t.Fatalf("expected service-account impersonation to be detected: %#v", findings)
	}
}

func TestOrdinarySSHIsSafe(t *testing.T) {
	content := "gcloud compute ssh myinstance\n"
	findings := identityFindings(t, "deploy.sh", content)
	if hasRule(findings, "SKIL-ID-IMPERSONATION") {
		t.Fatalf("an ordinary SSH command without impersonation should not fire: %#v", findings)
	}
}

func TestLongLivedStaticCredentialIsDetected(t *testing.T) {
	content := "service_account_key = get_static_credential('deployer')\n"
	findings := identityFindings(t, "auth.py", content)
	if !hasRule(findings, "SKIL-ID-LONG-LIVED-TOKEN") {
		t.Fatalf("expected a long-lived static credential reference to be detected: %#v", findings)
	}
}

func TestShortLivedTokenIsSafe(t *testing.T) {
	content := "token = get_oidc_token(audience='ci.example.com')\n"
	findings := identityFindings(t, "auth.py", content)
	if hasRule(findings, "SKIL-ID-LONG-LIVED-TOKEN") {
		t.Fatalf("an OIDC-based token should not fire the long-lived token rule: %#v", findings)
	}
}

func TestBroadIAMWildcardIsDetected(t *testing.T) {
	content := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}` + "\n"
	findings := identityFindings(t, "policy.json", content)
	if !hasRule(findings, "SKIL-ID-BROAD-SCOPE") {
		t.Fatalf("expected a wildcard Action+Resource policy to be detected: %#v", findings)
	}
}

func TestScopedIAMPolicyIsSafe(t *testing.T) {
	content := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}` + "\n"
	findings := identityFindings(t, "policy.json", content)
	if hasRule(findings, "SKIL-ID-BROAD-SCOPE") {
		t.Fatalf("a scoped IAM policy should not fire: %#v", findings)
	}
}
