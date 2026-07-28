package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/baseline"
	"github.com/domehahn/skil/internal/contracts"
	"github.com/domehahn/skil/internal/eval"
	"github.com/domehahn/skil/internal/evidence"
	"github.com/domehahn/skil/internal/importer"
	"github.com/domehahn/skil/internal/lockfile"
	"github.com/domehahn/skil/internal/packagecheck"
	"github.com/domehahn/skil/internal/policy"
	"github.com/domehahn/skil/internal/provider/osv"
	semanticprovider "github.com/domehahn/skil/internal/provider/semantic"
	"github.com/domehahn/skil/internal/report"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/internal/verification"
	"github.com/domehahn/skil/pkg/skil"
	"github.com/domehahn/skil/schemas"
	"gopkg.in/yaml.v3"
)

const (
	ExitOK       = 0
	ExitGateFail = 1
	ExitInput    = 2
	ExitInternal = 3
)

type App struct {
	Out, Err io.Writer
	Registry *analyzer.Registry
}

func New(out, errOut io.Writer) *App {
	return &App{Out: out, Err: errOut, Registry: analyzer.DefaultRegistry(nil)}
}

func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.help()
		return ExitInput
	}
	for _, arg := range args[1:] {
		if arg == "--help" || arg == "-h" {
			a.help()
			return ExitOK
		}
	}
	var code int
	switch args[0] {
	case "help", "--help", "-h":
		a.help()
		return ExitOK
	case "version", "--version":
		fmt.Fprintln(a.Out, skil.Version)
		return ExitOK
	case "validate":
		code = a.validate(args[1:])
	case "scan":
		code = a.scan(ctx, args[1:])
	case "verify":
		code = a.verify(ctx, args[1:])
	case "eval":
		code = a.evaluate(ctx, args[1:])
	case "attest":
		code = a.attest(ctx, args[1:])
	case "provenance":
		code = a.provenance(args[1:])
	case "key":
		code = a.key(args[1:])
	case "package":
		code = a.packageBuild(args[1:])
	case "install":
		code = a.install(ctx, args[1:])
	case "lock":
		code = a.lock(args[1:])
	case "evidence":
		code = a.evidence(args[1:])
	case "policy":
		code = a.policyCheck(ctx, args[1:])
	case "baseline":
		code = a.baselineCreate(ctx, args[1:])
	case "rules":
		code = a.rules(args[1:])
	case "analyzers":
		code = a.analyzers(args[1:])
	case "capabilities":
		code = a.capabilities(args[1:])
	case "inspect":
		code = a.inspect(args[1:])
	default:
		fmt.Fprintf(a.Err, "unknown command %q\n", args[0])
		a.help()
		return ExitInput
	}
	return code
}

func (a *App) help() {
	fmt.Fprint(a.Out, `skil - security, verification, and assurance for AI agent skills

Usage:
  skil validate <skill> [--format json]
  skil scan <skill> [--static-only] [--osv] [--yara-rules file] [--semantic --semantic-model model]
             [--format terminal|json|markdown|sarif] [--output file] [--baseline file]
  skil verify <skill> [--format json]
  skil eval <skill> [--test file] [--runtime mock|process] [--runtime-command executable] [--runs N]
  skil attest <skill> [--output file] [--signing-key key.pem] [--key-id id]
  skil provenance create <skill.tgz> --repository URL --commit SHA --builder ID --signing-key key.pem
  skil key generate --output key.pem
  skil package build <skill> --output skill.tgz
  skil package sign <skill.tgz> --signing-key key.pem --output package-signature.json
  skil install <skill.tgz> --destination dir --policy file --package-signature file --attestation file --provenance file
  skil lock verify <skill.tgz> --lock agent-skills.lock
  skil evidence sign <skill> --sarif report.sarif --signing-key key.pem --output evidence.json
  skil policy check <skill> --policy file [--package-signature file] [--attestation file] [--provenance file]
  skil baseline create <skill> [--output file] [--approved-by name] [--reason text]
  skil rules list | show <rule-id>
  skil analyzers list
  skil capabilities
  skil inspect <skill>

Exit codes: 0 passed, 1 security/policy gate failed, 2 invalid input/config, 3 internal failure.
`)
}

func (a *App) validate(args []string) int {
	fs := newFlags("validate", a.Err)
	format := fs.String("format", "terminal", "terminal or json")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	contract, path, err := contracts.Find(art)
	skillFile := findSkillFile(art)
	var packageResult packagecheck.Result
	if err == nil {
		packageResult = packagecheck.Validate(art, *contract)
	}
	valid := err == nil && skillFile != "" && len(packageResult.Errors) == 0
	result := map[string]any{"valid": valid, "artifact": art, "contract_file": path, "skill_file": skillFile}
	if err != nil {
		result["errors"] = []string{err.Error()}
	}
	if skillFile == "" {
		result["errors"] = appendString(result["errors"], "no SKILL.md discovered")
	}
	for _, packageError := range packageResult.Errors {
		result["errors"] = appendString(result["errors"], packageError)
	}
	if *format == "json" {
		_ = writeJSON(a.Out, result)
	} else {
		if valid {
			fmt.Fprintf(a.Out, "VALID %s (%s)\n", contract.Skill.Name, path)
		} else {
			fmt.Fprintf(a.Out, "INVALID %v\n", result["errors"])
		}
	}
	if !valid {
		return ExitInput
	}
	return ExitOK
}

func (a *App) scan(ctx context.Context, args []string) int {
	fs := newFlags("scan", a.Err)
	format := fs.String("format", "terminal", "output format")
	output := fs.String("output", "", "output file")
	staticOnly := fs.Bool("static-only", false, "disable semantic providers")
	useOSV := fs.Bool("osv", false, "query osv.dev for pinned dependency vulnerabilities")
	yaraRules := fs.String("yara-rules", "", "trusted YARA source-rules file")
	yaraBinary := fs.String("yara-binary", "yara", "YARA executable")
	useSemantic := fs.Bool("semantic", false, "enable external semantic analysis")
	semanticEndpoint := fs.String("semantic-endpoint", "https://api.openai.com/v1/chat/completions", "OpenAI-compatible chat endpoint")
	semanticModel := fs.String("semantic-model", "", "semantic model identifier")
	semanticKeyEnv := fs.String("semantic-api-key-env", "OPENAI_API_KEY", "environment variable containing API key")
	semanticAllowPrivate := fs.Bool("semantic-allow-private", false, "allow explicitly configured private/local semantic endpoint")
	baselinePath := fs.String("baseline", "", "baseline file")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *staticOnly && *useSemantic {
		return a.inputError(errors.New("--static-only and --semantic are mutually exclusive"))
	}
	var vulnerabilityProvider skil.VulnerabilityProvider
	if *useOSV {
		vulnerabilityProvider = osv.New()
	}
	registry := analyzer.DefaultRegistry(vulnerabilityProvider)
	if *yaraRules != "" {
		yaraAnalyzer, err := analyzer.NewYARA(*yaraBinary, *yaraRules)
		if err != nil {
			return a.inputError(err)
		}
		if err := registry.Register(yaraAnalyzer); err != nil {
			return a.internalError(err)
		}
	}
	if *useSemantic {
		if *semanticModel == "" {
			return a.inputError(errors.New("--semantic-model is required with --semantic"))
		}
		fmt.Fprintf(a.Err, "semantic analysis: provider=openai-compatible model=%s endpoint=%s transmission=all text files up to 1 MiB tools=none\n",
			*semanticModel, *semanticEndpoint)
		provider, err := semanticprovider.New(semanticprovider.Config{Endpoint: *semanticEndpoint, Model: *semanticModel,
			APIKey: os.Getenv(*semanticKeyEnv), AllowPrivate: *semanticAllowPrivate})
		if err != nil {
			return a.inputError(err)
		}
		semanticAnalyzer, err := analyzer.NewSemantic(provider)
		if err != nil {
			return a.internalError(err)
		}
		if err := registry.Register(semanticAnalyzer); err != nil {
			return a.internalError(err)
		}
	}
	result, _, err := a.performScanWithRegistry(ctx, fs.Arg(0), *baselinePath, registry)
	if err != nil {
		return a.inputError(err)
	}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if err := report.Write(writer, *format, result); err != nil {
		return a.inputError(err)
	}
	if result.Status == skil.StatusFail {
		return ExitGateFail
	}
	return ExitOK
}

func (a *App) verify(ctx context.Context, args []string) int {
	fs := newFlags("verify", a.Err)
	format := fs.String("format", "terminal", "terminal or json")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	scan, contract, err := a.performScan(ctx, fs.Arg(0), "")
	if err != nil {
		return a.inputError(err)
	}
	if contract == nil {
		return a.inputError(errors.New("verification requires skil.yaml"))
	}
	result := verification.Verify(*contract, scan.Findings)
	if *format == "json" {
		_ = writeJSON(a.Out, result)
	} else {
		fmt.Fprintf(a.Out, "Verification: %s\n", result.Status)
		for _, mismatch := range result.Mismatches {
			fmt.Fprintf(a.Out, "- %s: %s\n", mismatch.Capability, mismatch.Kind)
		}
	}
	if result.Status == skil.StatusFail {
		return ExitGateFail
	}
	return ExitOK
}

func (a *App) attest(ctx context.Context, args []string) int {
	fs := newFlags("attest", a.Err)
	output := fs.String("output", "", "output file")
	signingKey := fs.String("signing-key", "", "PKCS#8 PEM Ed25519 private key")
	keyID := fs.String("key-id", "", "trusted signing key identifier (defaults to public-key fingerprint)")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	scan, _, err := a.performScan(ctx, fs.Arg(0), "")
	if err != nil {
		return a.inputError(err)
	}
	attestation := evidence.Create(scan)
	if *signingKey != "" {
		privateKey, err := signing.LoadPrivateKey(*signingKey)
		if err != nil {
			return a.inputError(err)
		}
		if err := signing.SignAttestation(&attestation, privateKey, *keyID); err != nil {
			return a.internalError(err)
		}
	}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if err := writeJSON(writer, attestation); err != nil {
		return a.internalError(err)
	}
	return ExitOK
}

func (a *App) provenance(args []string) int {
	if len(args) == 0 || args[0] != "create" {
		fmt.Fprintln(a.Err, "usage: skil provenance create <skill> --repository URL --commit SHA --builder ID")
		return ExitInput
	}
	fs := newFlags("provenance create", a.Err)
	repository := fs.String("repository", "", "canonical source repository")
	commit := fs.String("commit", "", "immutable source commit")
	builder := fs.String("builder", "", "builder identity")
	output := fs.String("output", "", "output file")
	signingKey := fs.String("signing-key", "", "PKCS#8 PEM Ed25519 private key")
	keyID := fs.String("key-id", "", "trusted signing key identifier")
	if code := parse(fs, args[1:], 1); code != ExitOK {
		return code
	}
	if *repository == "" || *commit == "" || *builder == "" || *signingKey == "" {
		return a.inputError(errors.New("--repository, --commit, --builder, and --signing-key are required"))
	}
	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	if art.PackageDigest == "" {
		return a.inputError(errors.New("provenance requires a packaged artifact (.tgz or .zip)"))
	}
	provenance, err := signing.CreateProvenance(art.Name, art.PackageDigest, *repository, *commit, *builder, time.Now().UTC())
	if err != nil {
		return a.internalError(err)
	}
	privateKey, err := signing.LoadPrivateKey(*signingKey)
	if err != nil {
		return a.inputError(err)
	}
	if err := signing.SignProvenance(&provenance, privateKey, *keyID); err != nil {
		return a.internalError(err)
	}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if err := writeJSON(writer, provenance); err != nil {
		return a.internalError(err)
	}
	return ExitOK
}

func (a *App) key(args []string) int {
	if len(args) == 0 || args[0] != "generate" {
		fmt.Fprintln(a.Err, "usage: skil key generate --output key.pem")
		return ExitInput
	}
	fs := newFlags("key generate", a.Err)
	output := fs.String("output", "", "new private-key file (created with mode 0600; never overwritten)")
	if code := parse(fs, args[1:], 0); code != ExitOK {
		return code
	}
	if *output == "" {
		return a.inputError(errors.New("--output is required"))
	}
	keyID, publicKey, err := signing.GeneratePrivateKey(*output)
	if err != nil {
		return a.inputError(err)
	}
	returnCode := writeJSON(a.Out, map[string]string{"key_id": keyID, "public_key": publicKey, "private_key": *output})
	if returnCode != nil {
		return a.internalError(returnCode)
	}
	return ExitOK
}

func (a *App) packageBuild(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.Err, "usage: skil package build|sign")
		return ExitInput
	}
	if args[0] == "sign" {
		return a.packageSign(args[1:])
	}
	if args[0] != "build" {
		return a.inputError(errors.New("usage: skil package build <skill> --output skill.tgz"))
	}
	fs := newFlags("package build", a.Err)
	output := fs.String("output", "", "new deterministic .tgz package (never overwritten)")
	if code := parse(fs, args[1:], 1); code != ExitOK {
		return code
	}
	if *output == "" {
		return a.inputError(errors.New("--output is required"))
	}
	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	contract, _, err := contracts.Find(art)
	if err != nil {
		return a.inputError(err)
	}
	if err := packagecheck.Error(packagecheck.Validate(art, *contract)); err != nil {
		return a.inputError(err)
	}
	if err := packagecheck.WriteTGZ(*output, art); err != nil {
		return a.inputError(err)
	}
	packaged, err := artifact.Load(*output, artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	return boolCode(writeJSON(a.Out, map[string]string{
		"package": *output, "name": contract.Skill.Name, "version": contract.Skill.Version,
		"package_sha256": packaged.PackageDigest, "content_manifest_sha256": packaged.Digest,
	}), a)
}

func (a *App) packageSign(args []string) int {
	fs := newFlags("package sign", a.Err)
	signingKey := fs.String("signing-key", "", "PKCS#8 PEM Ed25519 private key")
	keyID := fs.String("key-id", "", "trusted signing key identifier")
	output := fs.String("output", "", "detached package signature")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *signingKey == "" || *output == "" {
		return a.inputError(errors.New("--signing-key and --output are required"))
	}
	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	if art.PackageDigest == "" {
		return a.inputError(errors.New("package signing requires an archive"))
	}
	contract, _, err := contracts.Find(art)
	if err != nil {
		return a.inputError(err)
	}
	privateKey, err := signing.LoadPrivateKey(*signingKey)
	if err != nil {
		return a.inputError(err)
	}
	statement := skil.PackageStatement{Version: 1, Name: contract.Skill.Name, VersionName: contract.Skill.Version,
		PackageSHA256: art.PackageDigest, ContentManifestSHA256: art.Digest, Timestamp: time.Now().UTC()}
	if err := signing.SignPackageStatement(&statement, privateKey, *keyID); err != nil {
		return a.internalError(err)
	}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	return boolCode(writeJSON(writer, statement), a)
}

func (a *App) install(ctx context.Context, args []string) int {
	fs := newFlags("install", a.Err)
	destination := fs.String("destination", "", "installation root")
	lockPath := fs.String("lock", "agent-skills.lock", "lockfile to update")
	expectedDigest := fs.String("expected-package-digest", "", "required package-blob SHA-256")
	policyPath := fs.String("policy", "", "mandatory installation policy")
	packageSignaturePath := fs.String("package-signature", "", "detached package signature")
	attestationPath := fs.String("attestation", "", "signed scan attestation")
	provenancePath := fs.String("provenance", "", "signed DSSE SLSA provenance")
	evidencePaths := fs.String("evidence", "", "comma-separated signed external evidence bundles")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *destination == "" || *policyPath == "" || *packageSignaturePath == "" || *attestationPath == "" || *provenancePath == "" {
		return a.inputError(errors.New("--destination, --policy, --package-signature, --attestation, and --provenance are required"))
	}
	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	if art.PackageDigest == "" {
		return a.inputError(errors.New("install requires an archive package"))
	}
	if *expectedDigest != "" && art.PackageDigest != *expectedDigest {
		return a.inputError(fmt.Errorf("package digest mismatch: expected %s, got %s", *expectedDigest, art.PackageDigest))
	}
	contract, _, err := contracts.Find(art)
	if err != nil {
		return a.inputError(err)
	}
	if err := packagecheck.Error(packagecheck.Validate(art, *contract)); err != nil {
		return a.inputError(err)
	}
	p, err := policy.Load(*policyPath)
	if err != nil {
		return a.inputError(err)
	}
	var packageStatement skil.PackageStatement
	var attestation skil.Attestation
	var provenance skil.Provenance
	if err := readStructured(*packageSignaturePath, &packageStatement, "package-signature-v1.schema.json"); err != nil {
		return a.inputError(err)
	}
	if err := readStructured(*attestationPath, &attestation, "attestation-v1.schema.json"); err != nil {
		return a.inputError(err)
	}
	if attestation.Signature == nil {
		return a.inputError(errors.New("installation requires a signed attestation"))
	}
	if err := readStructured(*provenancePath, &provenance, "provenance-v1.schema.json"); err != nil {
		return a.inputError(err)
	}
	var externalEvidence []skil.EvidenceBundle
	for _, evidencePath := range splitNonEmpty(*evidencePaths) {
		var bundle skil.EvidenceBundle
		if err := readStructured(evidencePath, &bundle, "evidence-bundle-v1.schema.json"); err != nil {
			return a.inputError(err)
		}
		externalEvidence = append(externalEvidence, bundle)
	}
	scan, _, err := a.performScan(ctx, fs.Arg(0), "")
	if err != nil {
		return a.inputError(err)
	}
	decision := policy.Check(p, policy.Input{Scan: scan, Contract: contract, Attestation: &attestation,
		Provenance: &provenance, PackageStatement: &packageStatement, ExternalEvidence: externalEvidence})
	if decision.Decision != "ALLOW" {
		_ = writeJSON(a.Err, decision)
		return ExitGateFail
	}
	if !safePackageIdentity(contract.Skill.Name) || !safePackageIdentity(contract.Skill.Version) {
		return a.inputError(errors.New("skill name/version is unsafe for installation"))
	}
	target := filepath.Join(*destination, contract.Skill.Name+"-"+contract.Skill.Version)
	if err := packagecheck.Install(target, art); err != nil {
		return a.inputError(err)
	}
	lock, err := lockfile.Load(*lockPath)
	if err == nil {
		lock = lockfile.Put(lock, lockfile.Entry{
			Name: contract.Skill.Name, Version: contract.Skill.Version, Source: fs.Arg(0),
			PackageSHA256: art.PackageDigest, ContentSHA256: art.Digest,
			Signature: *packageSignaturePath, Provenance: *provenancePath,
		})
		err = lockfile.Write(*lockPath, lock)
	}
	if err != nil {
		_ = os.RemoveAll(target)
		return a.inputError(fmt.Errorf("update lockfile; installation rolled back: %w", err))
	}
	return boolCode(writeJSON(a.Out, map[string]string{
		"installed": target, "lockfile": *lockPath, "package_sha256": art.PackageDigest,
		"content_manifest_sha256": art.Digest, "policy_decision": decision.Decision,
	}), a)
}

func (a *App) lock(args []string) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(a.Err, "usage: skil lock verify <skill.tgz> --lock agent-skills.lock")
		return ExitInput
	}
	fs := newFlags("lock verify", a.Err)
	path := fs.String("lock", "agent-skills.lock", "lockfile")
	if code := parse(fs, args[1:], 1); code != ExitOK {
		return code
	}
	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	contract, _, err := contracts.Find(art)
	if err != nil {
		return a.inputError(err)
	}
	lock, err := lockfile.Load(*path)
	if err != nil {
		return a.inputError(err)
	}
	if err := lockfile.Verify(lock, contract.Skill.Name, contract.Skill.Version, fs.Arg(0), art.PackageDigest, art.Digest); err != nil {
		return a.inputError(err)
	}
	fmt.Fprintf(a.Out, "LOCKED %s@%s package=%s content=%s\n", contract.Skill.Name, contract.Skill.Version, art.PackageDigest, art.Digest)
	return ExitOK
}

func safePackageIdentity(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func splitNonEmpty(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (a *App) evidence(args []string) int {
	if len(args) == 0 || args[0] != "sign" {
		fmt.Fprintln(a.Err, "usage: skil evidence sign <skill> --sarif report.sarif --signing-key key.pem --output evidence.json")
		return ExitInput
	}
	fs := newFlags("evidence sign", a.Err)
	sarifPath := fs.String("sarif", "", "SARIF 2.1.0 report with skil subject digest binding")
	signingKey := fs.String("signing-key", "", "PKCS#8 PEM Ed25519 private key")
	keyID := fs.String("key-id", "", "trusted signing key identifier")
	output := fs.String("output", "", "signed evidence bundle")
	if code := parse(fs, args[1:], 1); code != ExitOK {
		return code
	}
	if *sarifPath == "" || *signingKey == "" {
		return a.inputError(errors.New("--sarif and --signing-key are required"))
	}
	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	data, err := os.ReadFile(*sarifPath)
	if err != nil {
		return a.inputError(err)
	}
	imported, err := (importer.SARIF{}).Import(context.Background(), data, art)
	if err != nil {
		return a.inputError(err)
	}
	if len(imported) != 1 {
		return a.inputError(fmt.Errorf("SARIF evidence signing requires exactly one run, got %d", len(imported)))
	}
	privateKey, err := signing.LoadPrivateKey(*signingKey)
	if err != nil {
		return a.inputError(err)
	}
	bundle := skil.EvidenceBundle{Version: 1, Evidence: imported[0], Payload: json.RawMessage(data)}
	if err := signing.SignEvidenceBundle(&bundle, privateKey, *keyID); err != nil {
		return a.internalError(err)
	}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if err := writeJSON(writer, bundle); err != nil {
		return a.internalError(err)
	}
	return ExitOK
}

func (a *App) policyCheck(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(a.Err, "usage: skil policy check <skill> --policy file")
		return ExitInput
	}
	fs := newFlags("policy check", a.Err)
	path := fs.String("policy", "", "policy file")
	format := fs.String("format", "terminal", "terminal or json")
	attestationPath := fs.String("attestation", "", "attestation JSON or YAML")
	provenancePath := fs.String("provenance", "", "provenance JSON or YAML")
	packageSignaturePath := fs.String("package-signature", "", "detached package signature JSON or YAML")
	evidencePaths := fs.String("evidence", "", "comma-separated signed external evidence bundles")
	if code := parse(fs, args[1:], 1); code != ExitOK {
		return code
	}
	if *path == "" {
		return a.inputError(errors.New("--policy is required"))
	}
	p, err := policy.Load(*path)
	if err != nil {
		return a.inputError(err)
	}
	scan, contract, err := a.performScan(ctx, fs.Arg(0), "")
	if err != nil {
		return a.inputError(err)
	}
	var attestation *skil.Attestation
	if *attestationPath != "" {
		attestation = &skil.Attestation{}
		if err := readStructured(*attestationPath, attestation, "attestation-v1.schema.json"); err != nil {
			return a.inputError(err)
		}
	}
	var provenance *skil.Provenance
	if *provenancePath != "" {
		provenance = &skil.Provenance{}
		if err := readStructured(*provenancePath, provenance, "provenance-v1.schema.json"); err != nil {
			return a.inputError(err)
		}
	}
	var packageStatement *skil.PackageStatement
	if *packageSignaturePath != "" {
		packageStatement = &skil.PackageStatement{}
		if err := readStructured(*packageSignaturePath, packageStatement, "package-signature-v1.schema.json"); err != nil {
			return a.inputError(err)
		}
	}
	var externalEvidence []skil.EvidenceBundle
	for _, evidencePath := range splitNonEmpty(*evidencePaths) {
		var bundle skil.EvidenceBundle
		if err := readStructured(evidencePath, &bundle, "evidence-bundle-v1.schema.json"); err != nil {
			return a.inputError(err)
		}
		externalEvidence = append(externalEvidence, bundle)
	}
	result := policy.Check(p, policy.Input{
		Scan: scan, Contract: contract, Attestation: attestation, Provenance: provenance,
		PackageStatement: packageStatement, ExternalEvidence: externalEvidence,
	})
	if *format == "json" {
		_ = writeJSON(a.Out, result)
	} else {
		fmt.Fprintf(a.Out, "Policy decision: %s\n", result.Decision)
		for _, v := range result.Violations {
			fmt.Fprintf(a.Out, "- %s: %s (expected %v, observed %v)\n", v.Rule, v.Message, v.Expected, v.Observed)
		}
	}
	if result.Decision == "DENY" {
		return ExitGateFail
	}
	return ExitOK
}

func (a *App) baselineCreate(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] != "create" {
		fmt.Fprintln(a.Err, "usage: skil baseline create <skill>")
		return ExitInput
	}
	fs := newFlags("baseline create", a.Err)
	output := fs.String("output", "", "output file")
	approved := fs.String("approved-by", "unapproved", "approver identity")
	reason := fs.String("reason", "initial baseline; requires review", "approval reason")
	if code := parse(fs, args[1:], 1); code != ExitOK {
		return code
	}
	scan, _, err := a.performScan(ctx, fs.Arg(0), "")
	if err != nil {
		return a.inputError(err)
	}
	file := baseline.Create(scan.Findings, *approved, *reason)
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	encoder := yaml.NewEncoder(writer)
	encoder.SetIndent(2)
	if err := encoder.Encode(file); err != nil {
		return a.internalError(err)
	}
	return ExitOK
}

func (a *App) evaluate(ctx context.Context, args []string) int {
	fs := newFlags("eval", a.Err)
	testPath := fs.String("test", "", "behavioral test YAML")
	runtimeName := fs.String("runtime", "mock", "runtime id")
	runtimeCommand := fs.String("runtime-command", "", "explicit process adapter executable")
	runtimeArgs := fs.String("runtime-args", "", "comma-separated process adapter arguments")
	maxOutput := fs.Int64("max-output-bytes", 1<<20, "maximum runtime stdout bytes")
	runs := fs.Int("runs", 1, "number of runs")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *runtimeName != "mock" && *runtimeName != "process" {
		return a.inputError(fmt.Errorf("runtime %q is unavailable", *runtimeName))
	}
	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	if *testPath == "" {
		*testPath = discoverEval(art)
	}
	if *testPath == "" {
		return a.inputError(errors.New("no eval file found; use --test"))
	}
	var data []byte
	for _, file := range art.Files {
		if file.Path == *testPath {
			data = file.Data
		}
	}
	if data == nil {
		data, err = os.ReadFile(*testPath)
		if err != nil {
			return a.inputError(err)
		}
	}
	var spec skil.EvalSpec
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&spec); err != nil {
		return a.inputError(err)
	}
	if spec.Version != 1 || (spec.Type != "behavioral" && spec.Type != "adversarial") {
		return a.inputError(errors.New("invalid eval version or type"))
	}
	var runtime skil.AgentRuntime = eval.MockRuntime{}
	if *runtimeName == "process" {
		if *runtimeCommand == "" {
			return a.inputError(errors.New("--runtime-command is required for process runtime"))
		}
		contract, _, err := contracts.Find(art)
		if err != nil {
			return a.inputError(err)
		}
		timeout := time.Duration(contract.Capabilities.Resources.MaxRuntimeSeconds) * time.Second
		runtime = eval.ProcessRuntime{Executable: *runtimeCommand, Args: splitNonEmpty(*runtimeArgs),
			Timeout: timeout, MaxOutput: *maxOutput, MaxMemoryMB: contract.Capabilities.Resources.MaxMemoryMB}
	}
	result := eval.Run(ctx, runtime, spec, art, *runs)
	_ = writeJSON(a.Out, result)
	if result.Status == skil.StatusFail {
		return ExitGateFail
	}
	return ExitOK
}

func (a *App) rules(args []string) int {
	all := allRules()
	if len(args) == 0 || args[0] == "list" {
		for _, rule := range all {
			fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s\n", rule.ID, rule.Severity, rule.Category, rule.Title)
		}
		return ExitOK
	}
	if args[0] == "show" && len(args) == 2 {
		for _, rule := range all {
			if rule.ID == args[1] {
				_ = writeJSON(a.Out, rule)
				return ExitOK
			}
		}
		return a.inputError(fmt.Errorf("unknown rule %q", args[1]))
	}
	return a.inputError(errors.New("usage: skil rules list | show <rule-id>"))
}
func (a *App) analyzers(args []string) int {
	if len(args) > 0 && args[0] != "list" {
		return a.inputError(errors.New("usage: skil analyzers list"))
	}
	return boolCode(writeJSON(a.Out, a.Registry.Metadata()), a)
}
func (a *App) capabilities(args []string) int {
	if len(args) != 0 {
		return a.inputError(errors.New("capabilities takes no arguments"))
	}
	value := map[string]any{"analysis": map[string]bool{"pattern": true, "ast": true, "taint": true, "dependency": true, "mcp": true, "yara": false, "semantic": false, "behavioral": true},
		"providers": map[string][]string{"agent_runtime": {"mock", "process"}, "vulnerabilities": {"osv.dev"}, "semantic": {"openai-compatible"},
			"malware": {"yara-cli"}, "signing": {"builtin.ed25519"}, "evidence_importers": {"signed-sarif"}},
		"runtime_enforcement": true, "package_lockfile": true}
	if _, err := exec.LookPath("yara"); err == nil {
		value["analysis"].(map[string]bool)["yara"] = true
	}
	value["analysis"].(map[string]bool)["semantic"] = true
	return boolCode(writeJSON(a.Out, value), a)
}
func (a *App) inspect(args []string) int {
	fs := newFlags("inspect", a.Err)
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	contract, path, contractErr := contracts.Find(art)
	result := map[string]any{"artifact": art, "skill_file": findSkillFile(art), "contract_file": path, "contract": contract}
	if contractErr != nil {
		result["contract_error"] = contractErr.Error()
	}
	return boolCode(writeJSON(a.Out, result), a)
}

func (a *App) performScan(ctx context.Context, source, baselinePath string) (skil.ScanResult, *skil.SkillContract, error) {
	return a.performScanWithRegistry(ctx, source, baselinePath, a.Registry)
}

func (a *App) performScanWithRegistry(ctx context.Context, source, baselinePath string, registry *analyzer.Registry) (skil.ScanResult, *skil.SkillContract, error) {
	art, err := artifact.Load(source, artifact.Options{Exclude: []string{"vendor/**", "node_modules/**"}})
	if err != nil {
		return skil.ScanResult{}, nil, err
	}
	contract, _, contractErr := contracts.Find(art)
	if contractErr != nil {
		contract = nil
	}
	result, err := registry.Scan(ctx, skil.AnalysisContext{Artifact: art, Contract: contract})
	if err != nil {
		return result, contract, err
	}
	if contract != nil {
		verified := verification.Verify(*contract, result.Findings)
		result.Findings = append(result.Findings, verification.Findings(verified, art)...)
		result.Maximum, result.RiskScore, result.Status = analyzer.Risk(result.Findings, result.Coverage)
	}
	if baselinePath != "" {
		base, err := baseline.Load(baselinePath)
		if err != nil {
			return result, contract, err
		}
		result.Findings = baseline.Apply(result.Findings, base, time.Now().UTC())
		result.Maximum, result.RiskScore, result.Status = analyzer.Risk(result.Findings, result.Coverage)
	}
	result.GeneratedAt = time.Now().UTC()
	return result, contract, nil
}

func parse(fs *flag.FlagSet, args []string, positional int) int {
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return ExitInput
	}
	if fs.NArg() != positional {
		fs.Usage()
		return ExitInput
	}
	return ExitOK
}

// The standard flag package stops at the first positional argument. CLI users
// naturally write both "scan --format json path" and "scan path --format json",
// so normalize known flags before parsing while preserving positional order.
func interspersed(fs *flag.FlagSet, args []string) []string {
	flags, positionals := []string{}, []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		name := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
		def := fs.Lookup(name)
		if def == nil {
			flags = append(flags, arg)
			continue
		}
		flags = append(flags, arg)
		if strings.Contains(arg, "=") {
			continue
		}
		if boolFlag, ok := def.Value.(interface{ IsBoolFlag() bool }); ok && boolFlag.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}
func newFlags(name string, errOut io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() { fmt.Fprintf(errOut, "invalid arguments for skil %s; use skil --help\n", name) }
	return fs
}
func (a *App) inputError(err error) int { fmt.Fprintln(a.Err, "input error:", err); return ExitInput }
func (a *App) internalError(err error) int {
	fmt.Fprintln(a.Err, "internal error:", err)
	return ExitInternal
}
func boolCode(err error, a *App) int {
	if err != nil {
		return a.internalError(err)
	}
	return ExitOK
}
func writeJSON(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

func readStructured(path string, target any, schemaName ...string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(schemaName) == 1 {
		if err := schemas.ValidateYAML(schemaName[0], data); err != nil {
			return fmt.Errorf("validate %s: %w", path, err)
		}
	}
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		if err := json.Unmarshal(data, target); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		return nil
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}
func outputWriter(fallback io.Writer, path string) (io.Writer, func(), error) {
	if path == "" {
		return fallback, func() {}, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { _ = file.Close() }, nil
}
func findSkillFile(a skil.Artifact) string {
	for _, f := range a.Files {
		base := strings.ToUpper(filepath.Base(f.Path))
		if base == "SKILL.MD" && (filepath.Dir(f.Path) == "." || strings.Contains(filepath.ToSlash(f.Path), "/skills/")) {
			return f.Path
		}
	}
	return ""
}
func discoverEval(a skil.Artifact) string {
	for _, f := range a.Files {
		lower := strings.ToLower(f.Path)
		if strings.HasSuffix(lower, ".yaml") && (strings.Contains(lower, "eval") || strings.Contains(lower, "behavior")) {
			return f.Path
		}
	}
	return ""
}
func appendString(value any, item string) []string {
	if items, ok := value.([]string); ok {
		return append(items, item)
	}
	return []string{item}
}
func allRules() []skil.Rule {
	return analyzer.BuiltinRules()
}
