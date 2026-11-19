package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/domehahn/skil/internal/profile"
)

func (a *App) profileCommand(args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("profile requires a subcommand, e.g. skil profile check"))
	}

	switch args[0] {
	case "check", "validate":
		return a.profileCheck(args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown profile subcommand %q", args[0]))
	}
}

func (a *App) profileCheck(args []string) int {
	fs := newFlags("profile check", a.Err)
	configPath := fs.String("config", "", "path to deployment profile YAML/JSON file")
	profileFlag := fs.String("profile", "", "profile name to validate: development|secure|production")
	format := fs.String("format", "terminal", "terminal or json")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	var cfg profile.DeploymentConfig
	if strings.TrimSpace(*configPath) != "" {
		loaded, err := profile.LoadDeploymentConfig(*configPath)
		if err != nil {
			return a.inputError(err)
		}
		cfg = loaded
	} else {
		targetProf := profile.ProfileProduction
		if strings.TrimSpace(*profileFlag) != "" {
			targetProf = profile.ProfileName(strings.ToLower(strings.TrimSpace(*profileFlag)))
		}
		switch targetProf {
		case profile.ProfileDevelopment:
			cfg = profile.DefaultDevelopmentConfig()
		case profile.ProfileSecure:
			cfg = profile.DefaultSecureConfig()
		case profile.ProfileProduction:
			cfg = profile.DefaultProductionConfig()
		default:
			return a.inputError(fmt.Errorf("unsupported profile %q", targetProf))
		}
	}

	if strings.TrimSpace(*profileFlag) != "" {
		cfg.Profile = profile.ProfileName(strings.ToLower(strings.TrimSpace(*profileFlag)))
	}

	report := profile.ValidateStartup(cfg, profile.LiveEnvironmentState{})

	if *format == "json" {
		if err := writeJSON(a.Out, report); err != nil {
			return a.internalError(err)
		}
	} else {
		fmt.Fprintf(a.Out, "SKIL Deployment Profile Startup Validation\n")
		fmt.Fprintf(a.Out, "Profile:      %s\n", report.Profile)
		fmt.Fprintf(a.Out, "Environment:  %s\n", report.Environment)
		fmt.Fprintf(a.Out, "Topology:     %s\n", report.Topology)
		fmt.Fprintf(a.Out, "Status:       Valid=%t, Blocked=%t (Blocking findings: %d)\n\n",
			report.Valid, report.Blocked, report.BlockingCount)

		if len(report.Findings) > 0 {
			fmt.Fprintf(a.Out, "Validation Findings (%d):\n", len(report.Findings))
			for _, f := range report.Findings {
				blockTag := ""
				if f.Blocking {
					blockTag = " [BLOCKING]"
				}
				fmt.Fprintf(a.Out, "  - [%s]%s %s: %s\n", f.Severity, blockTag, f.ControlID, f.Evidence)
				fmt.Fprintf(a.Out, "         Expected:    %s\n", f.ExpectedConfig)
				fmt.Fprintf(a.Out, "         Remediation: %s\n", f.Remediation)
			}
		} else {
			fmt.Fprintf(a.Out, "No security findings recorded. All profile controls satisfied.\n")
		}

		fmt.Fprintf(a.Out, "\nSummary: %s\n", report.Summary)
	}

	if report.Blocked {
		return ExitGateFail
	}
	return ExitOK
}
