package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/domehahn/skil/internal/mcpinterceptor"
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

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	var gw *receipt.ExecutionGateway
	if *mandatoryAuth || strings.TrimSpace(*issuerPubKey) != "" {
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
