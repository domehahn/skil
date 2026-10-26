package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/domehahn/skil/internal/profile"
	"github.com/domehahn/skil/internal/runtimeproxy"
	"gopkg.in/yaml.v3"
)

func RunProxy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var format string
	var policyPath string
	var port int
	var profileFlag string
	var profileConfig string

	fs.StringVar(&format, "format", "terminal", "Output format: terminal|json|yaml")
	fs.StringVar(&policyPath, "policy", "", "Path to custom proxy policy YAML/JSON")
	fs.IntVar(&port, "port", 8080, "Port for host-mediated proxy")
	fs.StringVar(&profileFlag, "profile", "", "Deployment profile: development|secure|production")
	fs.StringVar(&profileConfig, "profile-config", "", "Path to deployment profile YAML/JSON")

	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return 2
	}

	posArgs := fs.Args()
	if len(posArgs) < 1 || posArgs[0] != "serve" {
		fmt.Fprintln(stderr, "Usage: skil proxy serve [--policy policy.yaml] [--profile development|secure|production] [--profile-config profile.yaml] [--port 8080] [--format terminal|json|yaml]")
		return 2
	}

	var deployCfg profile.DeploymentConfig
	hasProfile := false
	if strings.TrimSpace(profileConfig) != "" {
		loaded, err := profile.LoadDeploymentConfig(profileConfig)
		if err != nil {
			fmt.Fprintf(stderr, "Error loading deployment config: %v\n", err)
			return 1
		}
		deployCfg = loaded
		hasProfile = true
	} else if strings.TrimSpace(profileFlag) != "" {
		targetProf := profile.ProfileName(strings.ToLower(strings.TrimSpace(profileFlag)))
		switch targetProf {
		case profile.ProfileDevelopment:
			deployCfg = profile.DefaultDevelopmentConfig()
		case profile.ProfileSecure:
			deployCfg = profile.DefaultSecureConfig()
		case profile.ProfileProduction:
			deployCfg = profile.DefaultProductionConfig()
		default:
			fmt.Fprintf(stderr, "Error: unsupported deployment profile %q\n", targetProf)
			return 2
		}
		hasProfile = true
	}

	if hasProfile {
		if strings.TrimSpace(profileFlag) != "" {
			deployCfg.Profile = profile.ProfileName(strings.ToLower(strings.TrimSpace(profileFlag)))
		}
		valReport := profile.ValidateStartup(deployCfg, profile.LiveEnvironmentState{})
		if valReport.Blocked {
			fmt.Fprintf(stderr, "STARTUP VALIDATION BLOCKED (%s profile):\n", deployCfg.Profile)
			for _, f := range valReport.Findings {
				if f.Blocking {
					fmt.Fprintf(stderr, "  - [%s] %s: %s (Remediation: %s)\n", f.Severity, f.ControlID, f.Evidence, f.Remediation)
				}
			}
			return 1
		}
	}

	policy := runtimeproxy.DefaultProxyPolicy()
	if policyPath != "" {
		data, err := os.ReadFile(policyPath)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to read policy file: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(data, &policy); err != nil {
			if errY := yaml.Unmarshal(data, &policy); errY != nil {
				fmt.Fprintf(stderr, "Error: failed to parse policy file: %v\n", err)
				return 1
			}
		}
	}

	var outData []byte
	var err error

	switch format {
	case "json":
		outData, err = json.MarshalIndent(map[string]interface{}{
			"status": "ready",
			"port":   port,
			"policy": policy,
		}, "", "  ")
	case "yaml":
		outData, err = yaml.Marshal(map[string]interface{}{
			"status": "ready",
			"port":   port,
			"policy": policy,
		})
	default:
		outData = []byte(fmt.Sprintf(
			"SKIL Host-Mediated Runtime Proxy initialized\n"+
				"Port:               %d\n"+
				"Allowed Domains:    %v\n"+
				"Forbidden Commands: %v\n"+
				"PII Redaction:      %t\n",
			port, policy.AllowedDomains, policy.ForbiddenCommands, policy.RedactPII,
		))
	}

	if err != nil {
		fmt.Fprintf(stderr, "Error formatting output: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, string(outData))
	return 0
}
