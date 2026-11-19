package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/domehahn/skil/internal/gate"
	"github.com/domehahn/skil/internal/profile"
)

func (a *App) gate(args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("gate requires a subcommand, e.g. skil gate check or skil gate release"))
	}

	switch args[0] {
	case "check":
		return a.gateCheck(args[1:])
	case "release":
		return a.gateRelease(args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown gate subcommand %q", args[0]))
	}
}

func (a *App) gateCheck(args []string) int {
	fs := newFlags("gate check", a.Err)
	artifactPath := fs.String("artifact", "", "artifact directory or package blob to verify")
	attestationPath := fs.String("attestation", "", "attestation JSON file to verify")
	policyPath := fs.String("policy", "", "policy YAML file to enforce")
	format := fs.String("format", "terminal", "terminal or json")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	if *artifactPath == "" || *attestationPath == "" {
		return a.inputError(errors.New("--artifact and --attestation parameters are required for gate check"))
	}

	result, err := gate.CheckGate(gate.GateOptions{
		ArtifactPath:    *artifactPath,
		AttestationPath: *attestationPath,
		PolicyPath:      *policyPath,
	})

	if err != nil {
		return a.inputError(err)
	}

	if *format == "json" {
		if err := writeJSON(a.Out, result); err != nil {
			return a.internalError(err)
		}
	} else {
		if result.Allowed {
			fmt.Fprintf(a.Out, "ADMISSION APPROVED: %s\n", result.Reason)
			fmt.Fprintf(a.Out, "  Artifact SHA256:    %s\n", result.ArtifactDigest)
			fmt.Fprintf(a.Out, "  Attestation Subject: %s\n", result.AttestationSubject)
			if result.ClosureDigest != "" {
				fmt.Fprintf(a.Out, "  Closure SHA256:     %s\n", result.ClosureDigest)
			}
		} else {
			fmt.Fprintf(a.Err, "ADMISSION DENIED: %s\n", result.Reason)
			for _, v := range result.Violations {
				fmt.Fprintf(a.Err, "  - Violation [%s]: %s\n", v.Rule, v.Message)
			}
		}
	}

	if !result.Allowed {
		return ExitGateFail
	}

	return ExitOK
}

func (a *App) gateRelease(args []string) int {
	fs := newFlags("gate release", a.Err)
	configPath := fs.String("config", "", "path to deployment profile YAML/JSON file")
	profileFlag := fs.String("profile", "", "target profile: development|secure|production")
	attestationPath := fs.String("attestation", "", "optional path to attestation JSON to verify")
	policyPath := fs.String("policy", "", "optional path to policy YAML file to verify")
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

	report := profile.EvaluateReleaseGate(profile.ReleaseGateOptions{
		Config:          cfg,
		AttestationPath: *attestationPath,
		PolicyPath:      *policyPath,
	})

	if *format == "json" {
		if err := writeJSON(a.Out, report); err != nil {
			return a.internalError(err)
		}
	} else {
		fmt.Fprintf(a.Out, "SKIL Release Security Gate Report\n")
		fmt.Fprintf(a.Out, "Profile:     %s\n", report.Profile)
		fmt.Fprintf(a.Out, "Environment: %s\n", report.Environment)
		fmt.Fprintf(a.Out, "Topology:    %s\n", report.Topology)
		fmt.Fprintf(a.Out, "Status:      %s\n\n", report.Status)

		fmt.Fprintf(a.Out, "Release Security Checks (10-Point Verification):\n")
		for _, ch := range report.Checks {
			icon := "✓ PASS"
			if ch.Status == profile.CheckFail {
				icon = "✗ FAIL"
			} else if ch.Status == profile.CheckIncompl {
				icon = "? INCOMPLETE"
			} else if ch.Status == profile.CheckSkip {
				icon = "- SKIPPED"
			}
			fmt.Fprintf(a.Out, "  [%s] %s: %s\n", icon, ch.Name, ch.Detail)
			if ch.Remediation != "" && (ch.Status == profile.CheckFail || ch.Status == profile.CheckIncompl) {
				fmt.Fprintf(a.Out, "         Remediation: %s\n", ch.Remediation)
			}
		}

		if len(report.Findings) > 0 {
			fmt.Fprintf(a.Out, "\nStartup Validation Findings (%d):\n", len(report.Findings))
			for _, f := range report.Findings {
				blockTag := ""
				if f.Blocking {
					blockTag = " [BLOCKING]"
				}
				fmt.Fprintf(a.Out, "  - [%s]%s %s: %s (Remediation: %s)\n", f.Severity, blockTag, f.ControlID, f.Evidence, f.Remediation)
			}
		}

		fmt.Fprintf(a.Out, "\nSummary: %s\n", report.Summary)
	}

	if report.Status != profile.GateStatusReady {
		return ExitGateFail
	}
	return ExitOK
}
