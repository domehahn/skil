package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/domehahn/skil/internal/mcpinterceptor"
	"github.com/domehahn/skil/internal/profile"
	"github.com/domehahn/skil/internal/receipt"
)

func (a *App) mcpIntercept(args []string) int {
	fs := newFlags("mcp intercept", a.Err)
	lockPath := fs.String("lock", ".skil/mcp-surface.lock.json", "path to MCP surface lock file")
	strict := fs.Bool("strict", true, "enforce strict blocking of unauthorized dynamic tools")
	requireLock := fs.Bool("require-lock", false, "require a valid non-empty MCP surface lock file")
	mandatoryAuth := fs.Bool("mandatory-auth", false, "require proof-carrying ExecutionAuthorization on every tools/call")
	audience := fs.String("audience", "runtime://skil-mcp-interceptor", "expected runtime audience ID for proof-carrying authorization")
	issuer := fs.String("issuer", "", "trusted issuer ID for proof-carrying authorization")
	issuerKeyID := fs.String("issuer-key-id", "", "trusted issuer Ed25519 key ID")
	issuerPubKey := fs.String("issuer-pub-key", "", "trusted issuer Ed25519 public key (base64)")
	nonceDir := fs.String("nonce-dir", "", "optional directory for durable replay protection across restarts")
	profileFlag := fs.String("profile", "", "deployment profile: development|secure|production")
	profileConfig := fs.String("profile-config", "", "path to deployment profile configuration file")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	var deployCfg profile.DeploymentConfig
	hasProfile := false
	if strings.TrimSpace(*profileConfig) != "" {
		loaded, err := profile.LoadDeploymentConfig(*profileConfig)
		if err != nil {
			return a.inputError(err)
		}
		deployCfg = loaded
		hasProfile = true
	} else if strings.TrimSpace(*profileFlag) != "" {
		targetProf := profile.ProfileName(strings.ToLower(strings.TrimSpace(*profileFlag)))
		switch targetProf {
		case profile.ProfileDevelopment:
			deployCfg = profile.DefaultDevelopmentConfig()
		case profile.ProfileSecure:
			deployCfg = profile.DefaultSecureConfig()
		case profile.ProfileProduction:
			deployCfg = profile.DefaultProductionConfig()
		default:
			return a.inputError(fmt.Errorf("unsupported profile %q", targetProf))
		}
		hasProfile = true
	}

	if hasProfile {
		if strings.TrimSpace(*profileFlag) != "" {
			deployCfg.Profile = profile.ProfileName(strings.ToLower(strings.TrimSpace(*profileFlag)))
		}
		// If command-line flags provided, overlay them onto profile
		if *lockPath != ".skil/mcp-surface.lock.json" || deployCfg.MCP.SurfaceLockPath == "" {
			deployCfg.MCP.SurfaceLockPath = *lockPath
		}
		if *requireLock {
			deployCfg.MCP.RequireSurfaceLock = true
		}
		if *mandatoryAuth {
			deployCfg.Enforcement.MandatoryAuthorization = true
			deployCfg.Enforcement.RequireProofCarrying = true
		}
		if strings.TrimSpace(*audience) != "runtime://skil-mcp-interceptor" || deployCfg.Gateway.AudienceID == "" {
			deployCfg.Gateway.AudienceID = *audience
		}
		if strings.TrimSpace(*issuer) != "" && strings.TrimSpace(*issuerKeyID) != "" {
			if deployCfg.Gateway.TrustedIssuers == nil {
				deployCfg.Gateway.TrustedIssuers = make(map[string][]string)
			}
			deployCfg.Gateway.TrustedIssuers[*issuer] = []string{*issuerKeyID}
		}
		if strings.TrimSpace(*issuerKeyID) != "" && strings.TrimSpace(*issuerPubKey) != "" {
			if deployCfg.Gateway.TrustedPublicKeys == nil {
				deployCfg.Gateway.TrustedPublicKeys = make(map[string]string)
			}
			deployCfg.Gateway.TrustedPublicKeys[*issuerKeyID] = *issuerPubKey
		}
		if strings.TrimSpace(*nonceDir) != "" {
			deployCfg.Replay.DurableDir = *nonceDir
			deployCfg.Replay.Scope = receipt.ReplayScopeHostDurable
		}

		// Perform mandatory startup validation
		valReport := profile.ValidateStartup(deployCfg, profile.LiveEnvironmentState{})
		if valReport.Blocked {
			fmt.Fprintf(a.Err, "STARTUP VALIDATION BLOCKED (%s profile):\n", deployCfg.Profile)
			for _, f := range valReport.Findings {
				if f.Blocking {
					fmt.Fprintf(a.Err, "  - [%s] %s: %s (Remediation: %s)\n", f.Severity, f.ControlID, f.Evidence, f.Remediation)
				}
			}
			return ExitGateFail
		}

		// Propagate validated configuration to local variables
		*requireLock = deployCfg.MCP.RequireSurfaceLock
		*strict = deployCfg.MCP.StrictTools
		*mandatoryAuth = deployCfg.Enforcement.MandatoryAuthorization
		*lockPath = deployCfg.MCP.SurfaceLockPath
		*audience = deployCfg.Gateway.AudienceID
		if deployCfg.Replay.DurableDir != "" {
			*nonceDir = deployCfg.Replay.DurableDir
		}
	}

	var gw *receipt.ExecutionGateway
	if *mandatoryAuth || strings.TrimSpace(*issuerPubKey) != "" || (hasProfile && len(deployCfg.Gateway.TrustedPublicKeys) > 0) {
		var ledger *receipt.NonceLedger
		if strings.TrimSpace(*nonceDir) != "" {
			var err error
			ledger, err = receipt.NewDurableNonceLedger(*nonceDir)
			if err != nil {
				return a.inputError(err)
			}
		} else {
			ledger = receipt.NewNonceLedger()
		}
		issuers := map[string][]string{}
		pubKeys := map[string]string{}
		if hasProfile && len(deployCfg.Gateway.TrustedIssuers) > 0 {
			for k, v := range deployCfg.Gateway.TrustedIssuers {
				issuers[k] = append([]string(nil), v...)
			}
		}
		if hasProfile && len(deployCfg.Gateway.TrustedPublicKeys) > 0 {
			for k, v := range deployCfg.Gateway.TrustedPublicKeys {
				pubKeys[k] = v
			}
		}
		if strings.TrimSpace(*issuer) != "" && strings.TrimSpace(*issuerKeyID) != "" {
			issuers[strings.TrimSpace(*issuer)] = []string{strings.TrimSpace(*issuerKeyID)}
		}
		if strings.TrimSpace(*issuerKeyID) != "" && strings.TrimSpace(*issuerPubKey) != "" {
			pubKeys[strings.TrimSpace(*issuerKeyID)] = strings.TrimSpace(*issuerPubKey)
		}
		gw = receipt.NewExecutionGateway(receipt.ExecutionGatewayConfig{
			RuntimeAudienceID: *audience,
			TrustedIssuers:    issuers,
			TrustedPublicKeys: pubKeys,
			Nonces:            ledger,
		})
	}

	interceptor, err := mcpinterceptor.NewInterceptor(mcpinterceptor.InterceptorOptions{
		SurfaceLockPath:    *lockPath,
		Strict:             *strict,
		RequireSurfaceLock: *requireLock,
		MandatoryAuth:      *mandatoryAuth,
		Gateway:            gw,
	})
	if err != nil {
		return a.inputError(err)
	}

	if err := interceptor.RunStream(os.Stdin, a.Out, true); err != nil {
		return a.inputError(fmt.Errorf("mcp intercept stream: %w", err))
	}

	return ExitOK
}
