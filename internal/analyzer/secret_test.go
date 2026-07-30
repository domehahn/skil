package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func secretFindings(t *testing.T, content string) []skil.Finding {
	t.Helper()
	findings, err := NewSecret().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith("config.py", content)})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestHardcodedAWSKeyIsDetected(t *testing.T) {
	findings := secretFindings(t, `AWS_KEY = "AKIAIOSFODNN7EXAMPLE"`+"\n")
	if !hasRule(findings, "SKIL-SECRET-HARDCODED") {
		t.Fatalf("expected hardcoded AWS key to be detected: %#v", findings)
	}
}

func TestHardcodedGitHubTokenIsDetected(t *testing.T) {
	findings := secretFindings(t, `TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwx12"`+"\n")
	if !hasRule(findings, "SKIL-SECRET-TOKEN") {
		t.Fatalf("expected hardcoded GitHub token to be detected: %#v", findings)
	}
}

func TestHardcodedConnectionStringIsDetected(t *testing.T) {
	findings := secretFindings(t, `DB_URL = "postgresql://admin:SuperSecret123@db.internal:5432/prod"`+"\n")
	if !hasRule(findings, "SKIL-SECRET-CONNECTION-STRING") {
		t.Fatalf("expected credential-bearing connection string to be detected: %#v", findings)
	}
}

func TestEmbeddedPrivateKeyIsDetected(t *testing.T) {
	findings := secretFindings(t, "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----\n")
	if !hasRule(findings, "SKIL-SECRET-PRIVATE-KEY") {
		t.Fatalf("expected embedded private key to be detected: %#v", findings)
	}
}

func TestEnvironmentVariableReadIsNotFlaggedAsSecret(t *testing.T) {
	findings := secretFindings(t, `AWS_KEY = os.environ["AWS_ACCESS_KEY_ID"]`+"\n")
	if len(findings) != 0 {
		t.Fatalf("reading a secret from the environment is not an embedded secret: %#v", findings)
	}
}

func TestPlaceholderTokenIsNotFlaggedAsSecret(t *testing.T) {
	findings := secretFindings(t, `TOKEN = "your_github_token_here"`+"\n")
	if hasRule(findings, "SKIL-SECRET-TOKEN") {
		t.Fatalf("an obvious placeholder value should not fire: %#v", findings)
	}
}

func TestCredentialLessConnectionStringIsSafe(t *testing.T) {
	findings := secretFindings(t, `DB_URL = "postgresql://user@localhost:5432/dev"`+"\n")
	if hasRule(findings, "SKIL-SECRET-CONNECTION-STRING") {
		t.Fatalf("a connection string without an embedded password should not fire: %#v", findings)
	}
}

func TestPlaceholderPasswordIsSafe(t *testing.T) {
	findings := secretFindings(t, `password = "changeme"`+"\n")
	if hasRule(findings, "SKIL-SECRET-HARDCODED") {
		t.Fatalf("a placeholder password should not fire: %#v", findings)
	}
}

func TestDiscordBotTokenIsDetected(t *testing.T) {
	findings := secretFindings(t, `TOKEN = "000000000000000000000000.XXXXXX.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`+"\n")
	if !hasRule(findings, "SKIL-SECRET-TOKEN") {
		t.Fatalf("expected Discord bot token to be detected: %#v", findings)
	}
}

func TestTelegramBotTokenIsDetected(t *testing.T) {
	findings := secretFindings(t, `TOKEN = "1234567890:ABCdefGHIjklMNOpqrsTUVwxyzABCDEFGHIJklmno"`+"\n")
	if !hasRule(findings, "SKIL-SECRET-TOKEN") {
		t.Fatalf("expected Telegram bot token to be detected: %#v", findings)
	}
}

func TestNpmAccessTokenIsDetected(t *testing.T) {
	findings := secretFindings(t, `NPM_TOKEN = "npm_1234567890abcdef1234567890abcdef1234567890abcdef1234"`+"\n")
	if !hasRule(findings, "SKIL-SECRET-TOKEN") {
		t.Fatalf("expected npm access token to be detected: %#v", findings)
	}
}

func TestGitLabCIJobTokenIsDetected(t *testing.T) {
	findings := secretFindings(t, `CI_JOB_TOKEN = "glcbt-1234567890abcdef1234567890abcdef12345678"`+"\n")
	if !hasRule(findings, "SKIL-SECRET-TOKEN") {
		t.Fatalf("expected GitLab CI job token to be detected: %#v", findings)
	}
}
