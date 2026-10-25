// Package isolation provides the mandatory boundary for launching untrusted
// analysis providers: an explicit environment allowlist, never an inherited
// environment.
package isolation

import (
	"os"
	"os/exec"
	"strings"
)

// Environment builds a child environment from an explicit allowlist of names.
// Values are copied from the parent only for allowlisted names; everything
// else, including any credential-shaped variable, is dropped. Allowlisting a
// credential-shaped name is refused, so a policy typo cannot leak a secret.
func Environment(parent []string, allow []string) []string {
	ok := map[string]bool{}
	for _, n := range allow {
		if !credentialShaped(n) {
			ok[n] = true
		}
	}
	var out []string
	for _, kv := range parent {
		name, _, found := strings.Cut(kv, "=")
		if found && ok[name] {
			out = append(out, kv)
		}
	}
	return out
}

var secretMarkers = []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH", "COOKIE", "SESSION", "SSH", "AWS", "AZURE", "GCP", "GOOGLE", "GITHUB", "GITLAB", "NPM_", "KUBE", "DOCKER"}

func credentialShaped(name string) bool {
	upper := strings.ToUpper(name)
	for _, m := range secretMarkers {
		if strings.Contains(upper, m) {
			return true
		}
	}
	return false
}

// Command returns an exec.Cmd with an empty-by-default environment, a scratch
// working directory and no inherited stdin. The caller still owns network and
// filesystem confinement; this function guarantees only the environment and
// working-directory boundary and must never be bypassed by setting cmd.Env=nil
// (which would inherit the parent environment).
func Command(path string, args []string, workdir string, allow []string) *exec.Cmd {
	cmd := exec.Command(path, args...)
	cmd.Dir = workdir
	cmd.Env = append([]string{}, Environment(os.Environ(), allow)...)
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	return cmd
}
