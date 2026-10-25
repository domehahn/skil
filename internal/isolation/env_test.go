package isolation

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestEnvironmentAllowlistDropsEverythingElse(t *testing.T) {
	parent := []string{"PATH=/usr/bin", "LANG=C", "HOME=/home/u", "OPENAI_API_KEY=synthetic-key", "GIT_ASKPASS=/x", "SSH_AUTH_SOCK=/s"}
	got := Environment(parent, []string{"PATH", "LANG"})
	if len(got) != 2 || got[0] != "PATH=/usr/bin" || got[1] != "LANG=C" {
		t.Fatalf("%v", got)
	}
}

func TestCredentialShapedNamesCannotBeAllowlisted(t *testing.T) {
	parent := []string{"AWS_SECRET_ACCESS_KEY=s", "GITHUB_TOKEN=t", "MY_PASSWORD=p", "PATH=/bin", "SSH_AUTH_SOCK=/s", "NPM_TOKEN=n"}
	got := Environment(parent, []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "MY_PASSWORD", "SSH_AUTH_SOCK", "NPM_TOKEN", "PATH"})
	if len(got) != 1 || got[0] != "PATH=/bin" {
		t.Fatalf("a credential-shaped name was allowlisted: %v", got)
	}
}

// A real child process must not see synthetic credentials set in the parent.
func TestRealSubprocessDoesNotInheritSyntheticCredentials(t *testing.T) {
	secrets := map[string]string{
		"AWS_SECRET_ACCESS_KEY": "synthetic-aws", "GITHUB_TOKEN": "synthetic-gh", "OPENAI_API_KEY": "synthetic-oai",
		"SSH_AUTH_SOCK": "/synthetic/agent.sock", "GIT_ASKPASS": "/synthetic/askpass", "SKIL_TEST_CANARY": "synthetic-canary",
	}
	for k, v := range secrets {
		t.Setenv(k, v)
	}
	env, err := exec.LookPath("env")
	if err != nil {
		t.Skip("env(1) unavailable")
	}
	cmd := Command(env, nil, t.TempDir(), []string{"PATH"})
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for k, v := range secrets {
		if strings.Contains(text, k+"=") || strings.Contains(text, v) {
			t.Fatalf("child inherited %s:\n%s", k, text)
		}
	}
	if cmd.Dir == "" || cmd.Dir == mustGetwd(t) {
		t.Fatal("child must run in an isolated scratch directory")
	}
}

func mustGetwd(t *testing.T) string {
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNilEnvIsNeverProduced(t *testing.T) {
	if Command("/bin/true", nil, "", nil).Env == nil {
		t.Fatal("nil Env would inherit the parent environment")
	}
}
