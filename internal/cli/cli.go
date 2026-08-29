package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/domehahn/skil/compat/asps"
	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/internal/artifact"
	"github.com/domehahn/skil/internal/baseline"
	"github.com/domehahn/skil/internal/collection"
	"github.com/domehahn/skil/internal/conformance"
	"github.com/domehahn/skil/internal/contracts"
	"github.com/domehahn/skil/internal/eval"
	"github.com/domehahn/skil/internal/evidence"
	"github.com/domehahn/skil/internal/importer"
	"github.com/domehahn/skil/internal/lint"
	"github.com/domehahn/skil/internal/lockfile"
	"github.com/domehahn/skil/internal/packagecheck"
	"github.com/domehahn/skil/internal/policy"
	"github.com/domehahn/skil/internal/provider/consensus"
	"github.com/domehahn/skil/internal/provider/osv"
	reputationprovider "github.com/domehahn/skil/internal/provider/reputation"
	semanticprovider "github.com/domehahn/skil/internal/provider/semantic"
	"github.com/domehahn/skil/internal/report"
	"github.com/domehahn/skil/internal/sbom"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/internal/transitive"
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
	In       io.Reader
	Out, Err io.Writer
	Registry *analyzer.Registry
	logMu    sync.Mutex
}

type analysisFlags struct {
	full                 *bool
	staticOnly           *bool
	useOSV               *bool
	osvCache             *string
	osvOffline           *bool
	osvCacheTTL          *time.Duration
	yaraRules            *string
	yaraRulesDirectory   *string
	yaraBinary           *string
	yaraBuiltin          *bool
	useSemantic          *bool
	semanticProvider     *string
	semanticEndpoint     *string
	semanticModel        *string
	semanticKeyEnv       *string
	semanticAllowPrivate *bool
	semanticRegion       *string
	semanticAPIVersion   *string
	semanticValidation   *string
	semanticRuns         *int
	requireComplete      *bool
	failOnIncomplete     *bool
	allowRemote          *bool
	dependencyReputation *string
	domain               *string
	listDomains          *bool
}

func bindAnalysisFlags(fs *flag.FlagSet) analysisFlags {
	return analysisFlags{
		full:                 fs.Bool("full", false, "enable online OSV and the native malware signature pack; model semantic analysis remains explicit"),
		staticOnly:           fs.Bool("static-only", false, "disable semantic providers"),
		useOSV:               fs.Bool("osv", false, "query osv.dev for pinned dependency vulnerabilities"),
		osvCache:             fs.String("osv-cache", "", "optional OSV cache file"),
		osvOffline:           fs.Bool("osv-offline", false, "use only the configured OSV cache"),
		osvCacheTTL:          fs.Duration("osv-cache-ttl", time.Hour, "freshness window for OSV cache entries"),
		yaraRules:            fs.String("yara-rules", "", "trusted YARA source-rules file"),
		yaraRulesDirectory:   fs.String("yara-rules-dir", "", "flat directory of trusted .yar/.yara source files"),
		yaraBinary:           fs.String("yara-binary", "yara", "YARA executable"),
		yaraBuiltin:          fs.Bool("yara-builtin", false, "scan with skil's native conservative malware signature pack"),
		useSemantic:          fs.Bool("semantic", false, "enable external semantic analysis"),
		semanticProvider:     fs.String("semantic-provider", "openai-compatible", "semantic provider: openai-compatible, nvidia, anthropic, anthropic-proxy, or bedrock"),
		semanticEndpoint:     fs.String("semantic-endpoint", "https://api.openai.com/v1/chat/completions", "OpenAI-compatible chat endpoint"),
		semanticModel:        fs.String("semantic-model", "", "semantic model identifier"),
		semanticKeyEnv:       fs.String("semantic-api-key-env", "OPENAI_API_KEY", "environment variable containing API key"),
		semanticAllowPrivate: fs.Bool("semantic-allow-private", false, "allow explicitly configured private/local semantic endpoint"),
		semanticRegion:       fs.String("semantic-region", "us-west-2", "cloud region for the Bedrock semantic provider"),
		semanticAPIVersion:   fs.String("semantic-api-version", "", "optional Anthropic proxy API version"),
		semanticValidation:   fs.String("semantic-validation", "review", "semantic output validation: review or strict"),
		semanticRuns:         fs.Int("semantic-runs", 1, "independent semantic passes per request; a finding is kept only if a majority agree (Semantic Multi-Run Consensus)"),
		requireComplete:      fs.Bool("require-complete", false, "fail the gate unless every applicable inspection work item completed"),
		failOnIncomplete:     fs.Bool("fail-on-incomplete", false, "fail the gate if the scan exceeded its analysis budget (raw/expanded bytes, findings, inspection events, or wall time)"),
		allowRemote:          fs.Bool("allow-remote", false, "explicitly permit a public HTTPS archive or Git source"),
		dependencyReputation: fs.String("dependency-reputation", "", "trusted offline package-reputation JSON"),
		domain:               fs.String("domain", "", "only run analyzers matching this taxonomy domain (comma-separated)"),
		listDomains:          fs.Bool("list-domains", false, "list available taxonomy domains and exit"),
	}
}

func domainFilter(f analysisFlags) []string {
	if f.domain == nil || *f.domain == "" {
		return nil
	}
	return strings.Split(*f.domain, ",")
}

func New(out, errOut io.Writer) *App {
	return &App{In: os.Stdin, Out: out, Err: errOut, Registry: analyzer.DefaultRegistry(nil)}
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
		return a.version(args[1:])
	case "validate":
		code = a.validate(args[1:])
	case "lint":
		code = a.lint(args[1:])
	case "lint-all":
		code = a.lintAll(args[1:])
	case "scan":
		code = a.scan(ctx, args[1:])
	case "scan-all":
		code = a.scanAll(ctx, args[1:])
	case "compose":
		if len(args) > 1 && args[1] == "assure" {
			code = a.composeAssure(ctx, append([]string{}, args[2:]...))
		} else {
			code = a.compose(ctx, args[1:])
		}
	case "serve":
		code = a.serve(ctx, args[1:])
	case "mcp":
		code = a.mcp(ctx, args[1:])
	case "admission":
		code = a.admission(ctx, args[1:])
	case "verify":
		code = a.verify(ctx, args[1:])
	case "eval":
		code = a.evaluate(ctx, args[1:])
	case "assure":
		code = a.assure(ctx, args[1:])
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
	case "update":
		code = a.update(ctx, args[1:])
	case "uninstall":
		code = a.uninstall(args[1:])
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
	case "conform":
		code = a.conform(args[1:])
	case "analyzers":
		code = a.analyzers(args[1:])
	case "capabilities":
		code = a.capabilities(args[1:])
	case "inspect":
		code = a.inspect(args[1:])
	case "sbom":
		code = a.sbom(args[1:])
	case "discover":
		code = a.discover(args[1:])
	case "fix":
		code = a.fix(args[1:])
	case "watch":
		code = a.watch(ctx, args[1:])
	case "gate":
		code = a.gate(args[1:])
	case "hook":
		code = a.hook(args[1:])
	case "ci":
		code = a.ci(args[1:])
	case "contract":
		code = a.contract(ctx, args[1:])
	case "mesh":
		code = a.mesh(args[1:])
	case "stego":
		code = a.stego(args[1:])
	case "sandbox":
		code = a.sandbox(args[1:])
	case "revoke":
		code = a.revoke(args[1:])
	case "zk":
		code = a.zk(ctx, args[1:])
	default:
		fmt.Fprintf(a.Err, "unknown command %q\n", args[0])
		a.help()
		return ExitInput
	}
	return code
}

func (a *App) version(args []string) int {
	format := "plain"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
		} else if arg == "--format" && i+1 < len(args) {
			format = args[i+1]
		}
	}
	if format != "json" {
		fmt.Fprintln(a.Out, skil.Version)
		return ExitOK
	}
	value := map[string]any{"version": skil.Version, "prompt_version": semanticprovider.PromptVersion}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				value["commit"] = setting.Value
			}
			if setting.Key == "vcs.modified" {
				value["dirty"] = setting.Value == "true"
			}
		}
	}
	data, err := json.Marshal(value)
	if err != nil {
		return ExitInput
	}
	fmt.Fprintln(a.Out, string(data))
	return ExitOK
}

func (a *App) help() {
	fmt.Fprint(a.Out, `skil - Skill Inspector and Linter for AI agent skills

Usage:
  skil validate <skill> [--format json]
  skil lint <skill> [--strict|--profile default|strict|portable|publish] [--format terminal|json|markdown|sarif] [--output file]
  skil lint-all <collection> [--profile default|strict|portable|publish] [--workers N] [--format terminal|json|markdown] [--output file]
   skil scan <skill> [--full] [--static-only] [--osv] [--yara-rules file|--yara-rules-dir dir] [--semantic --semantic-model model] [--semantic-validation review|strict] [--semantic-runs N] [--require-complete] [--fail-on-incomplete] [--allow-remote]
              [--format terminal|json|markdown|sarif] [--compact] [--output file] [--baseline file] [--show-suppressed=false] [--domain domain] [--list-domains]
              [--transitive [--transitive-depth N] [--transitive-allow-prefix p1,p2] [--transitive-deny-prefix p1,p2]]
  skil scan-all <collection> [analysis flags] [--workers N] [--format terminal|json|markdown] [--output file]
  skil compose <collection> [analysis flags] [--format terminal|json] [--output file]
  skil compose assure <collection> --runtime-command executable [--runtime-args a,b] [--format terminal|json] [--output file]
  skil serve (--stdio | --listen 127.0.0.1:port --token-env ENV) --root <directory>
  skil mcp registry scan [file|server-name] [--official] [--format terminal|json] [--reviewed-closure contract]
  skil mcp assure <skill> --runtime-command executable [--runtime-args a,b] [--timeout 10s] [--format terminal|json] [--output file]
  skil verify <skill> [--format json] [--osv] [--yara-rules file] [--semantic --semantic-model model] [--semantic-validation review|strict] [--semantic-runs N]
  skil eval <skill> [--test file] [--runtime mock|isolated] [--runtime-command executable] [--runs N] [--output file]
  skil assure <skill> --runtime-command executable [--test file] [--runs N] [--full] [--format terminal|json]
  skil attest <skill> [--output file] [--eval-result file] [--signing-key key.pem] [analysis flags]
  skil provenance create <skill.tgz> --repository URL --commit SHA --builder ID --signing-key key.pem
  skil key generate --output key.pem
  skil package build <skill> --output skill.tgz
  skil package sign <skill.tgz> --signing-key key.pem --output package-signature.json
  skil install <skill.tgz> --destination dir --policy file --package-signature file --attestation file --provenance file [analysis flags]
  skil update <skill.tgz> --destination dir --policy file --package-signature file --attestation file --provenance file [analysis flags]
  skil uninstall <name> --destination dir [--lock agent-skills.lock]
  skil lock verify <skill.tgz> --lock agent-skills.lock
  skil evidence sign <skill> --sarif report.sarif --signing-key key.pem --output evidence.json
  skil policy init --output .skil/policy.yaml
  skil policy check <skill> --policy file [--eval-result file] [--package-signature file] [--attestation file] [--provenance file] [analysis flags]
  skil baseline create <skill> [--output file] [--approved-by name] [--reason text]
  skil rules list | show <rule-id>
  skil conform --profile core|identity|multi-agent|supply-chain|mcp|privacy|resilience|audit [--format json]
  skil admission serve --root dir --listen 127.0.0.1:port --policy file [--token-env VAR]
  skil analyzers list
  skil capabilities
  skil inspect <skill>
  skil sbom <skill> [--output sbom.spdx.json]
  skil discover [--home dir] [--format terminal|json] [--output file]

Exit codes: 0 passed, 1 security/policy gate failed, 2 invalid input/config, 3 internal failure.
`)
}

func (a *App) validate(args []string) int {
	fs := newFlags("validate", a.Err)
	format := fs.String("format", "terminal", "terminal, json, or markdown")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	art, err := artifact.Load(fs.Arg(0), artifact.Options{})
	if err != nil {
		return a.inputError(err)
	}
	contract, path, contractFormat, err := contracts.FindWithFormat(art)
	skillFile := findSkillFile(art)
	var packageResult packagecheck.Result
	if err == nil {
		if contractFormat == contracts.FormatUniversal {
			packageResult = packagecheck.ValidateAuthoring(art, *contract)
		} else {
			packageResult = packagecheck.Validate(art, *contract)
		}
	}
	valid := err == nil && skillFile != "" && len(packageResult.Errors) == 0
	result := map[string]any{
		"valid": valid, "artifact": art, "contract_file": path,
		"contract_format": contractFormat, "skill_file": skillFile,
	}
	if err != nil {
		result["errors"] = []string{err.Error()}
	}
	if skillFile == "" {
		if nested := nestedSkillFiles(art); len(nested) > 0 {
			result["errors"] = appendString(result["errors"],
				fmt.Sprintf("input contains %d nested skills; validate each concrete skill directory", len(nested)))
		} else {
			result["errors"] = appendString(result["errors"], "no SKILL.md discovered")
		}
	} else if err != nil {
		if nested := nestedSkillFiles(art); len(nested) > 0 {
			result["errors"] = appendString(result["errors"],
				fmt.Sprintf("no root skill contract; input contains %d nested skills; validate each concrete skill directory", len(nested)))
		}
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

func (a *App) lint(args []string) int {
	fs := newFlags("lint", a.Err)
	strict := fs.Bool("strict", false, "treat lint warnings as gate failures")
	profileName := fs.String("profile", string(lint.ProfileDefault), "lint profile: default, strict, portable, or publish")
	format := fs.String("format", "terminal", "terminal, json, markdown, or sarif")
	output := fs.String("output", "", "output file")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	profile, err := lint.ParseProfile(*profileName)
	if err != nil {
		return a.inputError(err)
	}
	if *strict && profile == lint.ProfileDefault {
		profile = lint.ProfileStrict
	}
	loaded, err := artifact.Load(fs.Arg(0), artifact.Options{
		Exclude: scanOutputExcludes(fs.Arg(0), *output),
	})
	if err != nil {
		return a.inputError(err)
	}
	result := lint.AnalyzeProfile(loaded, profile)
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if err := lint.Write(writer, *format, result); err != nil {
		return a.inputError(err)
	}
	if result.Status == skil.StatusFail {
		return ExitGateFail
	}
	return ExitOK
}

type lintCollectionResult struct {
	SchemaVersion string        `json:"schema_version"`
	Source        string        `json:"source"`
	Profile       lint.Profile  `json:"profile"`
	Skills        []lint.Result `json:"skills"`
	Passed        int           `json:"passed"`
	Warned        int           `json:"warned"`
	Failed        int           `json:"failed"`
}

func (a *App) lintAll(args []string) int {
	fs := newFlags("lint-all", a.Err)
	profileName := fs.String("profile", string(lint.ProfileDefault), "lint profile: default, strict, portable, or publish")
	format := fs.String("format", "terminal", "terminal, json, or markdown")
	output := fs.String("output", "", "output file")
	workers := fs.Int("workers", 1, "parallel skill lints (1-64)")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	profile, err := lint.ParseProfile(*profileName)
	if err != nil {
		return a.inputError(err)
	}
	if *format != "terminal" && *format != "json" && *format != "markdown" && *format != "md" {
		return a.inputError(errors.New("lint-all supports terminal, json, or markdown output"))
	}
	if *workers < 1 || *workers > 64 {
		return a.inputError(errors.New("--workers must be between 1 and 64"))
	}
	roots, err := collection.Discover(fs.Arg(0))
	if err != nil {
		return a.inputError(err)
	}
	if len(roots) == 0 {
		return a.inputError(errors.New("collection contains no SKILL.md files"))
	}
	result := lintCollectionResult{
		SchemaVersion: "1.0.0", Source: fs.Arg(0), Profile: profile,
		Skills: make([]lint.Result, len(roots)),
	}
	lintErrors := make([]error, len(roots))
	jobs := make(chan int)
	var group sync.WaitGroup
	workerCount := min(*workers, len(roots))
	for range workerCount {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				loaded, err := artifact.Load(roots[index], artifact.Options{
					Exclude: scanOutputExcludes(roots[index], *output),
				})
				if err != nil {
					lintErrors[index] = err
					continue
				}
				result.Skills[index] = lint.AnalyzeProfile(loaded, profile)
			}
		}()
	}
	for index := range roots {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	for index, err := range lintErrors {
		if err != nil {
			return a.inputError(fmt.Errorf("lint collection item %d: %w", index, err))
		}
		switch result.Skills[index].Status {
		case skil.StatusFail:
			result.Failed++
		case skil.StatusWarn:
			result.Warned++
		default:
			result.Passed++
		}
	}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if err := writeLintCollection(writer, *format, result); err != nil {
		return a.internalError(err)
	}
	if result.Failed > 0 {
		return ExitGateFail
	}
	return ExitOK
}

func writeLintCollection(writer io.Writer, format string, result lintCollectionResult) error {
	switch format {
	case "json":
		return writeJSON(writer, result)
	case "markdown", "md":
		fmt.Fprintf(writer, "# skil lint collection report\n\n- Source: `%s`\n- Profile: **%s**\n- Skills: **%d**\n- Passed: **%d**\n- Warned: **%d**\n- Failed: **%d**\n\n| Skill | Status | Errors | Warnings |\n|---|---|---:|---:|\n",
			report.MarkdownText(result.Source), result.Profile, len(result.Skills),
			result.Passed, result.Warned, result.Failed)
		for _, item := range result.Skills {
			fmt.Fprintf(writer, "| %s | %s | %d | %d |\n", report.MarkdownText(item.Artifact.Name),
				item.Status, item.Summary.Errors, item.Summary.Warnings)
		}
	default:
		fmt.Fprintf(writer, "skil lint collection report\n\nSource: %s\nProfile: %s\nSkills: %d\nPassed: %d\nWarned: %d\nFailed: %d\n\n",
			report.DisplayText(result.Source), result.Profile, len(result.Skills), result.Passed, result.Warned, result.Failed)
		for _, item := range result.Skills {
			fmt.Fprintf(writer, "- %s: %s (%d errors, %d warnings)\n",
				report.DisplayText(item.Artifact.Name), item.Status, item.Summary.Errors, item.Summary.Warnings)
		}
	}
	return nil
}

func (a *App) scan(ctx context.Context, args []string) int {
	fs := newFlags("scan", a.Err)
	format := fs.String("format", "terminal", "output format")
	output := fs.String("output", "", "output file")
	baselinePath := fs.String("baseline", "", "baseline file")
	showSuppressed := fs.Bool("show-suppressed", true, "include baseline-suppressed findings in reports")
	compact := fs.Bool("compact", false, "use the legacy one-line-per-finding terminal report")
	interactive := fs.Bool("interactive", false, "generate interactive HTML workbench report")
	transitiveFlag := fs.Bool("transitive", false, "follow external HTTPS references the skill's own content points at, recursively scanning each one (always off unless set; never on by default)")
	transitiveDepth := fs.Int("transitive-depth", transitive.DefaultDepth, "how many reference hops to follow (capped regardless of value)")
	transitiveAllow := fs.String("transitive-allow-prefix", "", "comma-separated URL prefixes; if set, only matching references are followed")
	transitiveDeny := fs.String("transitive-deny-prefix", "", "comma-separated URL prefixes that are never followed, overriding any allow-prefix match")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *interactive {
		*format = "interactive-html"
	}
	if *analysis.listDomains {
		for _, d := range analyzer.DefaultRegistry(nil).Domains() {
			fmt.Fprintln(a.Out, d)
		}
		return ExitOK
	}
	result, _, err := a.performScanConfiguredExcluding(
		ctx, fs.Arg(0), *baselinePath, analysis, scanOutputExcludes(fs.Arg(0), *output),
	)
	if err != nil {
		return a.inputError(err)
	}
	if *transitiveFlag {
		registry, err := a.analysisRegistry(ctx, analysis)
		if err != nil {
			return a.inputError(err)
		}
		scanner := func(ctx context.Context, path string) (skil.ScanResult, error) {
			childResult, _, err := a.performScanWithRegistry(ctx, path, "", registry)
			return childResult, err
		}
		result.References = transitive.Run(ctx, result.Artifact, transitive.Options{
			Depth: *transitiveDepth, AllowPrefixes: splitNonEmpty(*transitiveAllow), DenyPrefixes: splitNonEmpty(*transitiveDeny),
		}, httpsReferenceFetcher(), scanner)
		closure := transitive.BuildAssuranceClosureFromScan(result, result.References)
		result.Closure = &closure
		switch closure.State {
		case skil.AssuranceUnsafe:
			result.Status = skil.StatusFail
			result.Verdict = skil.VerdictBlock
			if severityRankCLI(closure.MaximumSeverity) > severityRankCLI(result.Maximum) {
				result.Maximum = closure.MaximumSeverity
			}
		case skil.AssuranceUnknown:
			if result.Status == skil.StatusPass {
				result.Status = skil.StatusWarn
			}
			if result.Verdict == skil.VerdictClear {
				result.Verdict = skil.VerdictReview
			}
		}
	}
	if *compact && *format != "terminal" && *format != "" {
		return a.inputError(errors.New("--compact is supported only with terminal output"))
	}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	reportResult := result
	if !*showSuppressed {
		reportResult.Findings = activeFindings(result.Findings)
	}
	if *compact {
		err = report.WriteCompact(writer, reportResult)
	} else {
		err = report.Write(writer, *format, reportResult)
	}
	if err != nil {
		return a.inputError(err)
	}
	if result.Status == skil.StatusFail {
		return ExitGateFail
	}
	return ExitOK
}

func activeFindings(findings []skil.Finding) []skil.Finding {
	active := make([]skil.Finding, 0, len(findings))
	for _, finding := range findings {
		if !finding.Suppressed {
			active = append(active, finding)
		}
	}
	return active
}

func severityRankCLI(severity skil.Severity) int {
	switch severity {
	case skil.SeverityCritical:
		return 4
	case skil.SeverityHigh:
		return 3
	case skil.SeverityMedium:
		return 2
	case skil.SeverityLow:
		return 1
	default:
		return 0
	}
}

type collectionScanResult struct {
	SchemaVersion string            `json:"schema_version"`
	Source        string            `json:"source"`
	Skills        []skil.ScanResult `json:"skills"`
	Passed        int               `json:"passed"`
	Failed        int               `json:"failed"`
}

func (a *App) scanAll(ctx context.Context, args []string) int {
	fs := newFlags("scan-all", a.Err)
	format := fs.String("format", "terminal", "terminal, json, or markdown")
	output := fs.String("output", "", "output file")
	baselinePath := fs.String("baseline", "", "baseline file applied to every skill")
	workers := fs.Int("workers", 1, "parallel skill scans (1-64)")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *analysis.listDomains {
		for _, d := range analyzer.DefaultRegistry(nil).Domains() {
			fmt.Fprintln(a.Out, d)
		}
		return ExitOK
	}
	if *format != "terminal" && *format != "json" && *format != "markdown" && *format != "md" {
		return a.inputError(errors.New("scan-all supports terminal, json, or markdown output"))
	}
	if *workers < 1 || *workers > 64 {
		return a.inputError(errors.New("--workers must be between 1 and 64"))
	}
	if *workers > 1 && analysis.osvCache != nil && *analysis.osvCache != "" {
		return a.inputError(errors.New("parallel scan-all cannot share --osv-cache; use --workers 1 or omit the cache"))
	}
	collectionSource, cleanup, err := stageRemoteSource(ctx, fs.Arg(0), analysis.allowRemote != nil && *analysis.allowRemote)
	if err != nil {
		return a.inputError(err)
	}
	defer cleanup()
	roots, err := collection.Discover(collectionSource)
	if err != nil {
		return a.inputError(err)
	}
	if len(roots) == 0 {
		return a.inputError(errors.New("collection contains no SKILL.md files"))
	}
	result := collectionScanResult{SchemaVersion: "1.0.0", Source: fs.Arg(0), Skills: make([]skil.ScanResult, len(roots))}
	scanErrors := make([]error, len(roots))
	jobs := make(chan int)
	var group sync.WaitGroup
	workerCount := *workers
	if workerCount > len(roots) {
		workerCount = len(roots)
	}
	for range workerCount {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				root := roots[index]
				scan, _, err := a.performScanConfiguredExcluding(ctx, root, *baselinePath, analysis, scanOutputExcludes(root, *output))
				if err != nil {
					scanErrors[index] = fmt.Errorf("scan %s: %w", root, err)
					continue
				}
				if collectionSource != fs.Arg(0) {
					relative, _ := filepath.Rel(collectionSource, root)
					scan.Artifact.Source = fs.Arg(0) + "#" + filepath.ToSlash(relative)
					scan.Artifact.Repository = fs.Arg(0)
				}
				result.Skills[index] = scan
			}
		}()
	}
	for index := range roots {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	for index, err := range scanErrors {
		if err != nil {
			return a.inputError(fmt.Errorf("collection item %d: %w", index, err))
		}
		if result.Skills[index].Status == skil.StatusFail {
			result.Failed++
		} else {
			result.Passed++
		}
	}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if *format == "json" {
		if err := writeJSON(writer, result); err != nil {
			return a.internalError(err)
		}
	} else if *format == "markdown" || *format == "md" {
		fmt.Fprintf(writer, "# skil collection report\n\n- Source: `%s`\n- Skills: **%d**\n- Passed: **%d**\n- Failed: **%d**\n\n| Skill | Status | Verdict | Findings | Inspection |\n|---|---|---|---:|---:|\n",
			report.MarkdownText(result.Source), len(result.Skills), result.Passed, result.Failed)
		for _, scan := range result.Skills {
			fmt.Fprintf(writer, "| %s | %s | %s | %d | %.1f%% |\n",
				report.MarkdownText(scan.Artifact.Name), scan.Status, scan.Verdict,
				len(scan.Findings), scan.Completeness.Completeness*100)
		}
	} else {
		fmt.Fprintf(writer, "skil collection report\n\nSource: %s\nSkills: %d\nPassed: %d\nFailed: %d\n\n",
			result.Source, len(result.Skills), result.Passed, result.Failed)
		for _, scan := range result.Skills {
			fmt.Fprintf(writer, "- %s: %s (%s, %d findings, %.1f%% complete)\n", scan.Artifact.Name,
				scan.Status, scan.Verdict, len(scan.Findings), scan.Completeness.Completeness*100)
		}
	}
	if result.Failed > 0 {
		return ExitGateFail
	}
	return ExitOK
}

func (a *App) verify(ctx context.Context, args []string) int {
	fs := newFlags("verify", a.Err)
	format := fs.String("format", "terminal", "terminal or json")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *analysis.listDomains {
		for _, d := range analyzer.DefaultRegistry(nil).Domains() {
			fmt.Fprintln(a.Out, d)
		}
		return ExitOK
	}
	scan, contract, err := a.performScanConfigured(ctx, fs.Arg(0), "", analysis)
	if err != nil {
		return a.inputError(err)
	}
	if contract == nil {
		return a.inputError(errors.New("verification requires skil.yaml"))
	}
	result := verification.Verify(*contract, scan.Findings, scan.Observations)
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
	evalResultPath := fs.String("eval-result", "", "behavioral/containment evaluation result JSON or YAML")
	signer := fs.String("signer", "file", "signing provider: file, pkcs11, yubikey, or hsm")
	slot := fs.Int("slot", 0, "hardware token slot index (when using hardware signers)")
	sessionBound := fs.Bool("session-bound", false, "bind prompt context, model parameters, and session memory digest")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *analysis.listDomains {
		for _, d := range analyzer.DefaultRegistry(nil).Domains() {
			fmt.Fprintln(a.Out, d)
		}
		return ExitOK
	}
	scan, _, err := a.performScanConfigured(ctx, fs.Arg(0), "", analysis)
	if err != nil {
		return a.inputError(err)
	}
	attestation := evidence.Create(scan)
	if *sessionBound {
		signing.BindSessionDigest(&attestation, signing.SessionContextOptions{
			SystemPrompt:  "Canonical Agent System Prompt",
			Temperature:   0.2,
			Seed:          42,
			SessionMemory: "Session State Memory Digest",
		})
	}
	if *evalResultPath != "" {
		var evalResult skil.EvalResult
		if err := readStructured(*evalResultPath, &evalResult, "eval-result-v1.schema.json"); err != nil {
			return a.inputError(err)
		}
		if err := evidence.AttachEval(&attestation, evalResult, scan.Artifact); err != nil {
			return a.inputError(err)
		}
	}
	if *signer != "file" && *signer != "" {
		var privateKey ed25519.PrivateKey
		if *signingKey != "" {
			var err error
			privateKey, err = signing.LoadPrivateKey(*signingKey)
			if err != nil {
				return a.inputError(err)
			}
		}
		opts := signing.HardwareSignerOptions{
			Provider: *signer,
			Slot:     *slot,
			KeyID:    *keyID,
		}
		if err := signing.SignAttestationHardware(&attestation, opts, privateKey); err != nil {
			return a.internalError(err)
		}
	} else if *signingKey != "" {
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
	return a.installOrUpdate(ctx, args, false)
}

func (a *App) update(ctx context.Context, args []string) int {
	return a.installOrUpdate(ctx, args, true)
}

func (a *App) installOrUpdate(ctx context.Context, args []string, replace bool) int {
	command := "install"
	if replace {
		command = "update"
	}
	fs := newFlags(command, a.Err)
	destination := fs.String("destination", "", "installation root")
	lockPath := fs.String("lock", "agent-skills.lock", "lockfile to update")
	expectedDigest := fs.String("expected-package-digest", "", "required package-blob SHA-256")
	policyPath := fs.String("policy", "", "mandatory installation policy")
	packageSignaturePath := fs.String("package-signature", "", "detached package signature")
	attestationPath := fs.String("attestation", "", "signed scan attestation")
	provenancePath := fs.String("provenance", "", "signed DSSE SLSA provenance")
	evidencePaths := fs.String("evidence", "", "comma-separated signed external evidence bundles")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *analysis.listDomains {
		for _, d := range analyzer.DefaultRegistry(nil).Domains() {
			fmt.Fprintln(a.Out, d)
		}
		return ExitOK
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
	scan, _, err := a.performScanConfigured(ctx, fs.Arg(0), "", analysis)
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
	lock, err := lockfile.Load(*lockPath)
	if err != nil {
		return a.inputError(err)
	}
	previous, installed := lockfile.Find(lock, contract.Skill.Name)
	if installed && !replace {
		return a.inputError(fmt.Errorf("skill %s is already installed; use skil update", contract.Skill.Name))
	}
	target := filepath.Join(*destination, contract.Skill.Name+"-"+contract.Skill.Version)
	previousTarget := ""
	if installed {
		if !safePackageIdentity(previous.Version) {
			return a.inputError(errors.New("installed skill version is unsafe"))
		}
		previousTarget = filepath.Join(*destination, previous.Name+"-"+previous.Version)
	}
	backup := ""
	if installed {
		if err := verifyInstalledTarget(previous, previousTarget); err != nil {
			return a.inputError(err)
		}
		backup, err = reserveSiblingPath(filepath.Dir(previousTarget), ".skil-update-backup-")
		if err != nil {
			return a.inputError(err)
		}
		if err := os.Rename(previousTarget, backup); err != nil {
			return a.inputError(fmt.Errorf("stage previous installation: %w", err))
		}
	}
	if err := packagecheck.Install(target, art); err != nil {
		if backup != "" {
			_ = os.Rename(backup, previousTarget)
		}
		return a.inputError(err)
	}
	lock = lockfile.Put(lock, lockfile.Entry{
		Name: contract.Skill.Name, Version: contract.Skill.Version, Source: fs.Arg(0),
		PackageSHA256: art.PackageDigest, ContentSHA256: art.Digest,
		Signature: *packageSignaturePath, Provenance: *provenancePath,
	})
	err = lockfile.Write(*lockPath, lock)
	if err != nil {
		_ = os.RemoveAll(target)
		if backup != "" {
			_ = os.Rename(backup, previousTarget)
		}
		return a.inputError(fmt.Errorf("update lockfile; installation rolled back: %w", err))
	}
	if backup != "" {
		if err := os.RemoveAll(backup); err != nil {
			return a.inputError(fmt.Errorf("remove previous installation backup: %w", err))
		}
	}
	return boolCode(writeJSON(a.Out, map[string]string{
		"installed": target, "lockfile": *lockPath, "package_sha256": art.PackageDigest,
		"content_manifest_sha256": art.Digest, "policy_decision": decision.Decision, "operation": command,
	}), a)
}

func (a *App) uninstall(args []string) int {
	fs := newFlags("uninstall", a.Err)
	destination := fs.String("destination", "", "installation root")
	lockPath := fs.String("lock", "agent-skills.lock", "lockfile to update")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	name := fs.Arg(0)
	if *destination == "" || !safePackageIdentity(name) {
		return a.inputError(errors.New("--destination and a safe skill name are required"))
	}
	lock, err := lockfile.Load(*lockPath)
	if err != nil {
		return a.inputError(err)
	}
	entry, ok := lockfile.Find(lock, name)
	if !ok {
		return a.inputError(fmt.Errorf("skill %s is not installed", name))
	}
	if !safePackageIdentity(entry.Version) {
		return a.inputError(errors.New("installed skill version is unsafe"))
	}
	target := filepath.Join(*destination, entry.Name+"-"+entry.Version)
	if err := verifyInstalledTarget(entry, target); err != nil {
		return a.inputError(err)
	}
	quarantine, err := reserveSiblingPath(filepath.Dir(target), ".skil-uninstall-")
	if err != nil {
		return a.inputError(err)
	}
	if err := os.Rename(target, quarantine); err != nil {
		return a.inputError(fmt.Errorf("stage uninstall: %w", err))
	}
	if err := lockfile.Write(*lockPath, lockfile.Remove(lock, name)); err != nil {
		_ = os.Rename(quarantine, target)
		return a.inputError(fmt.Errorf("update lockfile; uninstall rolled back: %w", err))
	}
	if err := os.RemoveAll(quarantine); err != nil {
		return a.inputError(fmt.Errorf("remove uninstalled skill: %w", err))
	}
	return boolCode(writeJSON(a.Out, map[string]string{
		"uninstalled": name, "removed": target, "lockfile": *lockPath,
	}), a)
}

func verifyInstalledTarget(entry lockfile.Entry, target string) error {
	if entry.ContentSHA256 == "" {
		return errors.New("destructive lifecycle operation requires a native content_manifest_sha256 lock")
	}
	installed, err := artifact.Load(target, artifact.Options{})
	if err != nil {
		return fmt.Errorf("load installed target: %w", err)
	}
	if installed.Digest != entry.ContentSHA256 {
		return fmt.Errorf("installed target content digest mismatch: expected %s, got %s", entry.ContentSHA256, installed.Digest)
	}
	return nil
}

func reserveSiblingPath(parent, pattern string) (string, error) {
	path, err := os.MkdirTemp(parent, pattern)
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return path, nil
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
	if len(args) > 0 {
		switch args[0] {
		case "init":
			return a.policyInit(ctx, args[1:])
		case "adapt":
			return a.policyAdapt(args[1:])
		}
	}
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(a.Err, "usage: skil policy init --output file | skil policy check <skill> --policy file")
		return ExitInput
	}
	fs := newFlags("policy check", a.Err)
	path := fs.String("policy", "", "policy file")
	format := fs.String("format", "terminal", "terminal or json")
	attestationPath := fs.String("attestation", "", "attestation JSON or YAML")
	provenancePath := fs.String("provenance", "", "provenance JSON or YAML")
	packageSignaturePath := fs.String("package-signature", "", "detached package signature JSON or YAML")
	evidencePaths := fs.String("evidence", "", "comma-separated signed external evidence bundles")
	evalResultPath := fs.String("eval-result", "", "behavioral/containment evaluation result JSON or YAML")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args[1:], 1); code != ExitOK {
		return code
	}
	if *analysis.listDomains {
		for _, d := range analyzer.DefaultRegistry(nil).Domains() {
			fmt.Fprintln(a.Out, d)
		}
		return ExitOK
	}
	if *path == "" {
		return a.inputError(errors.New("--policy is required"))
	}
	p, err := policy.Load(*path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return a.inputError(fmt.Errorf("policy %q not found; create one with `skil policy init --output %s`", *path, *path))
		}
		return a.inputError(err)
	}
	scan, contract, err := a.performScanConfigured(ctx, fs.Arg(0), "", analysis)
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
	var evalResult *skil.EvalResult
	if *evalResultPath != "" {
		evalResult = &skil.EvalResult{}
		if err := readStructured(*evalResultPath, evalResult, "eval-result-v1.schema.json"); err != nil {
			return a.inputError(err)
		}
	}
	result := policy.Check(p, policy.Input{
		Scan: scan, Contract: contract, Attestation: attestation, Provenance: provenance,
		PackageStatement: packageStatement, ExternalEvidence: externalEvidence, Eval: evalResult,
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

const defaultPolicy = `version: 1
maximum_severity: MEDIUM
required_analysis: [pattern, ast, taint, dependency, mcp]
minimum_inspection_completeness: 1
forbidden_capabilities: [network.outbound, secrets.read, commands.execute]
minimum_scans: 1
trusted_scanners: [skil]
trusted_scanner_keys: {}
trusted_signers: {}
trusted_builders: []
trusted_builder_keys: {}
allowed_repositories: []
allowed_registries: []
max_evidence_age: 7d
require_artifact_digest: true
require_signature: false
require_provenance: false
require_provenance_signature: false
require_behavioral_evaluation: false
require_containment_evaluation: false
require_runtime_enforcement: false
require_native_isolation: false
require_zero_forbidden_side_effects: false
`

func (a *App) policyInit(ctx context.Context, args []string) int {
	fs := newFlags("policy init", a.Err)
	output := fs.String("output", ".skil/policy.yaml", "new policy file (never overwritten)")
	fromTrace := fs.String("from-trace", "", "trace scan JSON, attestation JSON, or skill path to synthesize policy from")
	strict := fs.Bool("strict", false, "enable strict closure and execution bounds")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	policyContent := defaultPolicy

	if *fromTrace != "" {
		var scanResult skil.ScanResult
		// Try loading trace JSON first
		traceData, err := os.ReadFile(*fromTrace)
		if err == nil {
			_ = json.Unmarshal(traceData, &scanResult)
		}

		if scanResult.Artifact.Name == "" {
			// Perform scan on trace path
			scan, _, err := a.performScanConfigured(ctx, *fromTrace, "", analysis)
			if err != nil {
				return a.inputError(fmt.Errorf("scan trace target %s: %w", *fromTrace, err))
			}
			scanResult = scan
		}

		_, yamlStr, err := policy.SynthesizeFromScan(scanResult, *strict)
		if err != nil {
			return a.inputError(fmt.Errorf("synthesize policy from trace: %w", err))
		}
		policyContent = yamlStr
	}

	if err := os.MkdirAll(filepath.Dir(*output), 0o700); err != nil {
		return a.inputError(fmt.Errorf("create policy directory: %w", err))
	}
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return a.inputError(fmt.Errorf("create policy %q: %w", *output, err))
	}
	if _, err := io.WriteString(file, policyContent); err != nil {
		_ = file.Close()
		return a.internalError(fmt.Errorf("write policy %q: %w", *output, err))
	}
	if err := file.Close(); err != nil {
		return a.internalError(fmt.Errorf("close policy %q: %w", *output, err))
	}
	fmt.Fprintf(a.Out, "created policy %s\n", *output)
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
	file := baseline.CreateForScan(scan, *approved, *reason)
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
	output := fs.String("output", "", "evaluation result JSON")
	runtimeName := fs.String("runtime", "mock", "runtime id")
	runtimeCommand := fs.String("runtime-command", "", "executable for the isolated adapter")
	runtimeArgs := fs.String("runtime-args", "", "comma-separated process adapter arguments")
	maxOutput := fs.Int64("max-output-bytes", 1<<20, "maximum runtime stdout bytes")
	runs := fs.Int("runs", 1, "number of runs")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *runtimeName != "mock" && *runtimeName != "isolated" {
		return a.inputError(fmt.Errorf("runtime %q is unavailable", *runtimeName))
	}
	result, err := a.performEvaluation(ctx, fs.Arg(0), evaluationOptions{
		TestPath: *testPath, RuntimeName: *runtimeName, RuntimeCommand: *runtimeCommand,
		RuntimeArgs: *runtimeArgs, MaxOutput: *maxOutput, Runs: *runs,
	})
	if err != nil {
		return a.inputError(err)
	}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if err := writeJSON(writer, result); err != nil {
		return a.internalError(err)
	}
	if result.Status == skil.StatusFail {
		return ExitGateFail
	}
	return ExitOK
}

type evaluationOptions struct {
	TestPath, RuntimeName, RuntimeCommand, RuntimeArgs string
	MaxOutput                                          int64
	Runs                                               int
	RequireContainment                                 bool
	// Workspace overrides the isolated adapter's scratch workspace
	// directory. Empty (the default) creates and cleans up a fresh
	// directory per call, exactly the prior behavior. A non-empty value
	// is used as-is and never created/removed here — the caller owns its
	// lifecycle. skil compose assure sets this to one shared directory
	// across every skill in a collection, so a real write from one skill
	// and a real read from another can land on the same physical path.
	Workspace string
}

func (a *App) performEvaluation(ctx context.Context, source string, options evaluationOptions) (skil.EvalResult, error) {
	art, err := artifact.Load(source, artifact.Options{})
	if err != nil {
		return skil.EvalResult{}, err
	}
	return a.performEvaluationArtifact(ctx, art, options)
}

func (a *App) performEvaluationArtifact(ctx context.Context, art skil.Artifact, options evaluationOptions) (skil.EvalResult, error) {
	var err error
	testPath := options.TestPath
	if testPath == "" {
		testPath = discoverEval(art)
	}
	if testPath == "" {
		return skil.EvalResult{}, errors.New("no eval file found; use --test")
	}
	var data []byte
	for _, file := range art.Files {
		if file.Path == testPath {
			data = file.Data
		}
	}
	if data == nil {
		data, err = os.ReadFile(testPath)
		if err != nil {
			return skil.EvalResult{}, err
		}
	}
	if err := schemas.ValidateYAML("eval-v1.schema.json", data); err != nil {
		return skil.EvalResult{}, err
	}
	var spec skil.EvalSpec
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&spec); err != nil {
		return skil.EvalResult{}, err
	}
	if spec.Version != 1 || (spec.Type != "behavioral" && spec.Type != "adversarial") {
		return skil.EvalResult{}, errors.New("invalid eval version or type")
	}
	if options.RequireContainment && (spec.Containment == nil || !spec.Containment.Required ||
		!spec.Containment.RequireEnforcement || !spec.Containment.RequireNativeIsolation) {
		return skil.EvalResult{}, errors.New("assurance requires eval containment.required, require_enforcement, and require_native_isolation")
	}
	var runtime skil.AgentRuntime = eval.MockRuntime{}
	if options.RuntimeName == "isolated" {
		if options.RuntimeCommand == "" {
			return skil.EvalResult{}, errors.New("--runtime-command is required for isolated runtime")
		}
		contract, _, err := contracts.Find(art)
		if err != nil {
			return skil.EvalResult{}, err
		}
		timeout := time.Duration(contract.Capabilities.Resources.MaxRuntimeSeconds) * time.Second
		isolation, err := eval.NewNativeIsolation()
		if err != nil {
			return skil.EvalResult{}, err
		}
		workspace := options.Workspace
		if workspace == "" {
			workspace, err = os.MkdirTemp("", "skil-assurance-workspace-")
			if err != nil {
				return skil.EvalResult{}, err
			}
			defer os.RemoveAll(workspace)
		}
		runtime = eval.ProcessRuntime{Executable: options.RuntimeCommand, Args: splitNonEmpty(options.RuntimeArgs),
			Timeout: timeout, MaxOutput: options.MaxOutput, MaxMemoryMB: contract.Capabilities.Resources.MaxMemoryMB,
			Contract: *contract, Isolation: isolation,
			Tools: map[string]skil.GatewayTool{
				"artifact.read":        eval.NewArtifactReadTool(art),
				"workspace.read":       eval.NewWorkspaceReadTool(workspace),
				"workspace.write":      eval.NewWorkspaceWriteTool(workspace),
				"command.run":          eval.NewIsolatedCommandTool(isolation, options.MaxOutput),
				"network.get":          eval.NewNetworkGetTool(),
				"containment.simulate": eval.NewContainmentSimulationTool(),
			}}
	}
	return eval.Run(ctx, runtime, spec, art, options.Runs), nil
}

type assuranceResult struct {
	SchemaVersion      string              `json:"schema_version"`
	Status             skil.Status         `json:"status"`
	ArtifactDigest     string              `json:"artifact_digest"`
	Scan               skil.ScanResult     `json:"scan"`
	Verification       verification.Result `json:"verification"`
	Evaluation         skil.EvalResult     `json:"evaluation"`
	RuntimeEnforcement bool                `json:"runtime_enforcement"`
}

func (a *App) assure(ctx context.Context, args []string) int {
	fs := newFlags("assure", a.Err)
	testPath := fs.String("test", "", "behavioral/adversarial eval YAML with mandatory containment controls")
	runtimeCommand := fs.String("runtime-command", "", "executable for the isolated agent adapter")
	runtimeArgs := fs.String("runtime-args", "", "comma-separated isolated adapter arguments")
	maxOutput := fs.Int64("max-output-bytes", 1<<20, "maximum runtime stdout bytes")
	runs := fs.Int("runs", 1, "number of isolated assurance runs")
	format := fs.String("format", "terminal", "terminal or json")
	output := fs.String("output", "", "assurance result output")
	analysis := bindAnalysisFlags(fs)
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	if *analysis.listDomains {
		for _, d := range analyzer.DefaultRegistry(nil).Domains() {
			fmt.Fprintln(a.Out, d)
		}
		return ExitOK
	}
	if strings.TrimSpace(*runtimeCommand) == "" {
		return a.inputError(errors.New("assure requires --runtime-command for a real isolated agent adapter"))
	}
	if *format != "terminal" && *format != "json" {
		return a.inputError(errors.New("assure supports terminal or json output"))
	}
	scan, contract, err := a.performScanConfigured(ctx, fs.Arg(0), "", analysis)
	if err != nil {
		return a.inputError(err)
	}
	if contract == nil {
		return a.inputError(errors.New("assure requires a valid skill contract"))
	}
	verified := verification.Verify(*contract, scan.Findings, scan.Observations)
	evaluation, err := a.performEvaluationArtifact(ctx, scan.Artifact, evaluationOptions{
		TestPath: *testPath, RuntimeName: "isolated", RuntimeCommand: *runtimeCommand,
		RuntimeArgs: *runtimeArgs, MaxOutput: *maxOutput, Runs: *runs, RequireContainment: true,
	})
	if err != nil {
		return a.inputError(err)
	}
	if evaluation.ArtifactDigest != scan.Artifact.SubjectDigest() {
		return a.internalError(errors.New("assurance evaluation digest does not match scanned artifact"))
	}
	runtimeEnforcement := evaluation.Coverage.Enforcement == skil.CoverageCompleted &&
		evaluation.Coverage.Containment == skil.CoverageCompleted &&
		evaluation.Coverage.NativeIsolation == skil.CoverageCompleted
	status := skil.StatusPass
	if scan.Status == skil.StatusFail || verified.Status == skil.StatusFail ||
		evaluation.Status == skil.StatusFail || !runtimeEnforcement {
		status = skil.StatusFail
	} else if scan.Status == skil.StatusWarn || verified.Status == skil.StatusWarn {
		status = skil.StatusWarn
	}
	result := assuranceResult{
		SchemaVersion: "1.0.0", Status: status, ArtifactDigest: scan.Artifact.SubjectDigest(),
		Scan: scan, Verification: verified, Evaluation: evaluation, RuntimeEnforcement: runtimeEnforcement,
	}
	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if *format == "json" {
		err = writeJSON(writer, result)
	} else {
		fmt.Fprintf(writer, "skil assurance report\n\nArtifact digest: sha256:%s\nStatus: %s\nScan: %s (%s)\nVerification: %s\nBehavioral evaluation: %s\nRuntime enforcement: %t\nContainment: %s\nNative isolation: %s\n",
			result.ArtifactDigest, result.Status, result.Scan.Status, result.Scan.Verdict,
			result.Verification.Status, result.Evaluation.Status, result.RuntimeEnforcement,
			result.Evaluation.Coverage.Containment, result.Evaluation.Coverage.NativeIsolation)
	}
	if err != nil {
		return a.internalError(err)
	}
	if status == skil.StatusFail {
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

func (a *App) conform(args []string) int {
	var profileKey, format string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--profile":
			if i+1 >= len(args) {
				return a.inputError(errors.New("--profile requires a value"))
			}
			i++
			profileKey = args[i]
		case "--format":
			if i+1 >= len(args) {
				return a.inputError(errors.New("--format requires a value"))
			}
			i++
			format = args[i]
		default:
			return a.inputError(fmt.Errorf("usage: skil conform --profile %s [--format json]", strings.Join(conformance.ProfileNames(), "|")))
		}
	}
	if profileKey == "" {
		return a.inputError(fmt.Errorf("usage: skil conform --profile %s [--format json]", strings.Join(conformance.ProfileNames(), "|")))
	}
	reg, err := asps.Load()
	if err != nil {
		return a.internalError(err)
	}
	report, err := conformance.Evaluate(reg, profileKey)
	if err != nil {
		return a.inputError(err)
	}
	if format == "json" {
		return boolCode(writeJSON(a.Out, report), a)
	}
	fmt.Fprintf(a.Out, "ASPS Conformance: %s (snapshot %s)\n\n", report.Profile, report.Snapshot)
	fmt.Fprintf(a.Out, "Domain\tTotal\tImplemented\tPartial\tProvider\tMissing\tScore\n")
	for _, d := range report.Domains {
		fmt.Fprintf(a.Out, "%s (%s)\t%d\t%d\t%d\t%d\t%d\t%.1f%%\n",
			d.DomainName, d.DomainID, d.Total, d.Implemented, d.Partial, d.ProviderBacked, d.Missing, d.Score*100)
	}
	fmt.Fprintf(a.Out, "\nOverall: %.1f%% (%d properties)\n", report.Score*100, report.TotalProperties)
	return ExitOK
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
		"providers": map[string][]string{"agent_runtime": {"mock", "isolated"}, "vulnerabilities": {"osv.dev"}, "reputation": {"builtin-versioned-offline", "trusted-offline-json"},
			"semantic": {"openai-compatible", "nvidia", "anthropic", "anthropic-proxy", "aws-bedrock"},
			"malware":  {"builtin-native-signature-pack", "yara-source-file", "yara-source-directory"},
			"signing":  {"builtin.ed25519"}, "evidence_importers": {"signed-sarif"}},
		"lint": map[string]any{
			"available": true, "collection": true, "strict_gate": true,
			"profiles": []string{"default", "strict", "portable", "publish"},
			"formats":  []string{"terminal", "json", "markdown", "sarif"},
		},
		"package_lockfile": true, "collection_scanning": true, "remote_sources_opt_in": true,
		"mcp_registry_posture": true,
		"integrated_assurance": true,
		"collection_formats":   []string{"terminal", "json", "markdown"}, "collection_workers_max": 64,
		"baseline":   []string{"artifact-bound-fingerprint", "reviewed-glob", "expiry", "audit-reason"},
		"mcp_server": []string{"stdio", "authenticated-loopback-http"}}
	isolation, isolationErr := eval.NewNativeIsolation()
	nativeIsolation := map[string]any{"available": isolationErr == nil}
	if isolationErr == nil {
		nativeIsolation["provider"] = isolation.ID()
	}
	value["native_isolation"] = nativeIsolation
	value["runtime_enforcement"] = isolationErr == nil
	value["analysis"].(map[string]bool)["yara"] = true
	_, externalYARAErr := exec.LookPath("yara")
	value["external_yara_available"] = externalYARAErr == nil
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

func (a *App) sbom(args []string) int {
	fs := newFlags("sbom", a.Err)
	output := fs.String("output", "", "SBOM JSON output file")
	format := fs.String("format", "spdx", "spdx or cyclonedx")
	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}
	source := fs.Arg(0)

	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()

	if *format == "cyclonedx" {
		art, err := artifact.Load(source, artifact.Options{})
		if err != nil {
			return a.inputError(err)
		}
		doc, err := sbom.CreateCycloneDX(art, nil)
		if err != nil {
			return a.inputError(err)
		}
		return boolCode(writeJSON(writer, doc), a)
	}

	document, binaryErr := sbom.CreateGoBinary(source)
	if binaryErr != nil {
		if !errors.Is(binaryErr, sbom.ErrNotGoBinary) {
			return a.inputError(binaryErr)
		}
		art, err := artifact.Load(source, artifact.Options{})
		if err != nil {
			return a.inputError(err)
		}
		document, err = sbom.Create(art)
		if err != nil {
			return a.inputError(err)
		}
	}
	return boolCode(writeJSON(writer, document), a)
}

func (a *App) performScan(ctx context.Context, source, baselinePath string) (skil.ScanResult, *skil.SkillContract, error) {
	return a.performScanWithRegistry(ctx, source, baselinePath, a.Registry)
}

func (a *App) performScanConfigured(ctx context.Context, source, baselinePath string, flags analysisFlags) (skil.ScanResult, *skil.SkillContract, error) {
	return a.performScanConfiguredExcluding(ctx, source, baselinePath, flags, nil)
}

func (a *App) performScanConfiguredExcluding(
	ctx context.Context,
	source, baselinePath string,
	flags analysisFlags,
	excludes []string,
) (skil.ScanResult, *skil.SkillContract, error) {
	registry, err := a.analysisRegistry(ctx, flags)
	if err != nil {
		return skil.ScanResult{}, nil, err
	}
	staged, cleanup, err := stageRemoteSource(ctx, source, flags.allowRemote != nil && *flags.allowRemote)
	if err != nil {
		return skil.ScanResult{}, nil, err
	}
	defer cleanup()
	configuredExcludes := append([]string{"vendor/**", "node_modules/**"}, excludes...)
	if staged == source {
		configuredExcludes = append(configuredExcludes, scanOutputExcludes(source, baselinePath)...)
		if flags.osvCache != nil {
			configuredExcludes = append(configuredExcludes, scanOutputExcludes(source, *flags.osvCache)...)
		}
		if flags.yaraRules != nil {
			configuredExcludes = append(configuredExcludes, scanOutputExcludes(source, *flags.yaraRules)...)
		}
		if flags.dependencyReputation != nil {
			configuredExcludes = append(configuredExcludes, scanOutputExcludes(source, *flags.dependencyReputation)...)
		}
	}
	result, contract, err := a.performScanWithRegistryOptions(ctx, staged, baselinePath, registry, artifact.Options{
		Exclude: configuredExcludes,
	}, domainFilter(flags))
	if staged != source {
		result.Artifact.Source = source
		result.Artifact.Repository = source
	}
	if err == nil && flags.requireComplete != nil && *flags.requireComplete && result.Completeness.Completeness < 1 {
		result.Status = skil.StatusFail
		result.Verdict = skil.VerdictBlock
	}
	if err == nil && flags.failOnIncomplete != nil && *flags.failOnIncomplete && len(result.Budget.Exceeded) > 0 {
		result.Status = skil.StatusFail
		result.Verdict = skil.VerdictBlock
	}
	return result, contract, err
}

func (a *App) analysisRegistry(ctx context.Context, flags analysisFlags) (*analyzer.Registry, error) {
	if flags.staticOnly == nil {
		return nil, errors.New("analysis flags are not initialized")
	}
	if flags.full != nil && *flags.full {
		*flags.useOSV = true
		if *flags.yaraRules == "" && *flags.yaraRulesDirectory == "" && !*flags.yaraBuiltin {
			*flags.yaraBuiltin = true
		}
	}
	if *flags.staticOnly && *flags.useSemantic {
		return nil, errors.New("--static-only and --semantic are mutually exclusive")
	}
	builtinReputation, err := reputationprovider.LoadBuiltin()
	if err != nil {
		return nil, fmt.Errorf("load built-in dependency reputation: %w", err)
	}
	var vulnerabilityProvider skil.VulnerabilityProvider
	if *flags.useOSV || flags.osvOffline != nil && *flags.osvOffline {
		if flags.osvOffline != nil && *flags.osvOffline && *flags.osvCache == "" {
			return nil, errors.New("--osv-offline requires --osv-cache")
		}
		vulnerabilityProvider = osv.NewConfigured(osv.Config{
			CachePath: *flags.osvCache, CacheTTL: *flags.osvCacheTTL, Offline: *flags.osvOffline,
		})
	}
	reputationProviders := []skil.PackageReputationProvider{builtinReputation}
	if flags.dependencyReputation != nil && *flags.dependencyReputation != "" {
		reputation, err := reputationprovider.Load(*flags.dependencyReputation)
		if err != nil {
			return nil, err
		}
		reputationProviders = append(reputationProviders, reputation)
	}
	vulnerabilityProvider = combinedDependencyProvider{
		vulnerabilities: vulnerabilityProvider, reputation: reputationProviders,
	}
	registry := analyzer.DefaultRegistry(vulnerabilityProvider)
	if *flags.yaraRules != "" {
		yaraAnalyzer, err := analyzer.NewYARA(*flags.yaraBinary, *flags.yaraRules)
		if err != nil {
			return nil, err
		}
		if err := registry.Register(yaraAnalyzer); err != nil {
			return nil, err
		}
	}
	if flags.yaraRulesDirectory != nil && *flags.yaraRulesDirectory != "" {
		if *flags.yaraRules != "" || flags.yaraBuiltin != nil && *flags.yaraBuiltin {
			return nil, errors.New("--yara-rules-dir, --yara-rules, and --yara-builtin are mutually exclusive")
		}
		yaraAnalyzer, err := analyzer.NewYARADirectory(*flags.yaraBinary, *flags.yaraRulesDirectory)
		if err != nil {
			return nil, err
		}
		if err := registry.Register(yaraAnalyzer); err != nil {
			return nil, err
		}
	}
	if flags.yaraBuiltin != nil && *flags.yaraBuiltin {
		if *flags.yaraRules != "" {
			return nil, errors.New("--yara-builtin and --yara-rules are mutually exclusive")
		}
		yaraAnalyzer, err := analyzer.NewBuiltinYARA(*flags.yaraBinary)
		if err != nil {
			return nil, err
		}
		if err := registry.Register(yaraAnalyzer); err != nil {
			return nil, err
		}
	}
	if *flags.useSemantic {
		if *flags.semanticModel == "" {
			return nil, errors.New("--semantic-model is required with --semantic")
		}
		destination := *flags.semanticEndpoint
		if *flags.semanticProvider == "bedrock" {
			destination = "AWS Bedrock region " + *flags.semanticRegion
		}
		validationMode := skil.SemanticValidationMode(*flags.semanticValidation)
		a.logMu.Lock()
		fmt.Fprintf(a.Err, "semantic analysis: provider=%s model=%s destination=%s validation=%s transmission=all text files up to 1 MiB tools=none passes=security,intent,quality,policy,meta\n",
			*flags.semanticProvider, *flags.semanticModel, destination, validationMode)
		a.logMu.Unlock()
		var provider skil.SemanticProvider
		var err error
		switch *flags.semanticProvider {
		case "openai-compatible":
			provider, err = semanticprovider.New(semanticprovider.Config{
				Endpoint: *flags.semanticEndpoint, Model: *flags.semanticModel,
				APIKey: os.Getenv(*flags.semanticKeyEnv), AllowPrivate: *flags.semanticAllowPrivate,
				ValidationMode: validationMode,
			})
		case "nvidia":
			endpoint := *flags.semanticEndpoint
			if endpoint == "https://api.openai.com/v1/chat/completions" {
				endpoint = "https://integrate.api.nvidia.com/v1/chat/completions"
			}
			keyEnvironment := *flags.semanticKeyEnv
			if keyEnvironment == "OPENAI_API_KEY" {
				keyEnvironment = "NVIDIA_INFERENCE_KEY"
			}
			provider, err = semanticprovider.New(semanticprovider.Config{
				Endpoint: endpoint, Model: *flags.semanticModel,
				APIKey: os.Getenv(keyEnvironment), AllowPrivate: *flags.semanticAllowPrivate,
				ValidationMode: validationMode,
			})
		case "anthropic":
			endpoint := *flags.semanticEndpoint
			if endpoint == "https://api.openai.com/v1/chat/completions" {
				endpoint = "https://api.anthropic.com/v1/messages"
			}
			provider, err = semanticprovider.NewAnthropic(semanticprovider.AnthropicConfig{
				Endpoint: endpoint, Model: *flags.semanticModel,
				APIKey: os.Getenv(*flags.semanticKeyEnv), AllowPrivate: *flags.semanticAllowPrivate,
				ValidationMode: validationMode,
			})
		case "anthropic-proxy":
			keyEnvironment := *flags.semanticKeyEnv
			if keyEnvironment == "OPENAI_API_KEY" {
				keyEnvironment = "ANTHROPIC_PROXY_API_KEY"
			}
			provider, err = semanticprovider.NewAnthropicProxy(semanticprovider.AnthropicProxyConfig{
				Endpoint: *flags.semanticEndpoint, Model: *flags.semanticModel,
				BearerToken: os.Getenv(keyEnvironment), APIVersion: *flags.semanticAPIVersion,
				AllowPrivate: *flags.semanticAllowPrivate, ValidationMode: validationMode,
			})
		case "bedrock":
			provider, err = semanticprovider.NewBedrock(ctx, semanticprovider.BedrockConfig{
				Model: *flags.semanticModel, Region: *flags.semanticRegion, ValidationMode: validationMode,
			})
		default:
			return nil, fmt.Errorf("unsupported semantic provider %q", *flags.semanticProvider)
		}
		if err != nil {
			return nil, err
		}
		if *flags.semanticRuns < 1 {
			return nil, errors.New("--semantic-runs must be at least 1")
		}
		if *flags.semanticRuns > 1 {
			a.logMu.Lock()
			fmt.Fprintf(a.Err, "semantic multi-run consensus: %d independent passes per request; a finding is kept only if a majority agree\n", *flags.semanticRuns)
			a.logMu.Unlock()
			provider, err = consensus.New(provider, *flags.semanticRuns)
			if err != nil {
				return nil, err
			}
		}
		semanticAnalyzer, err := analyzer.NewSemanticSuite(provider)
		if err != nil {
			return nil, err
		}
		if err := registry.Register(semanticAnalyzer); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

type combinedDependencyProvider struct {
	vulnerabilities skil.VulnerabilityProvider
	reputation      []skil.PackageReputationProvider
}

func (combinedDependencyProvider) ID() string { return "combined-dependency-provider" }
func (p combinedDependencyProvider) VulnerabilityEnabled() bool {
	return p.vulnerabilities != nil
}
func (p combinedDependencyProvider) Query(ctx context.Context, ecosystem, name, version string) ([]skil.Vulnerability, error) {
	if p.vulnerabilities == nil {
		return nil, nil
	}
	return p.vulnerabilities.Query(ctx, ecosystem, name, version)
}
func (p combinedDependencyProvider) Reputation(ctx context.Context, ecosystem, name string) (skil.PackageReputation, error) {
	var combined skil.PackageReputation
	for _, provider := range p.reputation {
		reputation, err := provider.Reputation(ctx, ecosystem, name)
		if err != nil {
			return skil.PackageReputation{}, err
		}
		if reputation.Abandoned {
			combined = reputation
		}
	}
	return combined, nil
}

func (a *App) performScanWithRegistry(ctx context.Context, source, baselinePath string, registry *analyzer.Registry) (skil.ScanResult, *skil.SkillContract, error) {
	return a.performScanWithRegistryOptions(ctx, source, baselinePath, registry, artifact.Options{
		Exclude: []string{"vendor/**", "node_modules/**"},
	}, nil)
}

func (a *App) performScanWithRegistryOptions(
	ctx context.Context,
	source, baselinePath string,
	registry *analyzer.Registry,
	options artifact.Options,
	domainFilter []string,
) (skil.ScanResult, *skil.SkillContract, error) {
	art, err := artifact.Load(source, options)
	if err != nil {
		return skil.ScanResult{}, nil, err
	}
	contract, _, contractErr := contracts.Find(art)
	if contractErr != nil {
		contract = nil
	}
	result, err := registry.Scan(ctx, skil.AnalysisContext{Artifact: art, Contract: contract, DomainFilter: domainFilter})
	if err != nil {
		return result, contract, err
	}
	if contract != nil {
		verified := verification.Verify(*contract, result.Findings, result.Observations)
		result.Findings = append(result.Findings, verification.Findings(verified, art)...)
		result.Maximum, result.RiskScore, result.Status = analyzer.Risk(result.Findings, result.Coverage)
		result.Verdict = analyzer.Verdict(result.Maximum, result.RiskScore, result.Coverage)
	}
	if baselinePath != "" {
		base, err := baseline.Load(baselinePath)
		if err != nil {
			return result, contract, err
		}
		result.Findings = baseline.ApplyForArtifact(result.Findings, base, time.Now().UTC(), result.Artifact.SubjectDigest())
		result.Maximum, result.RiskScore, result.Status = analyzer.Risk(result.Findings, result.Coverage)
		result.Verdict = analyzer.Verdict(result.Maximum, result.RiskScore, result.Coverage)
	}
	result.GeneratedAt = time.Now().UTC()
	return result, contract, nil
}

func scanOutputExcludes(source, output string) []string {
	if output == "" {
		return nil
	}
	info, err := os.Stat(source)
	if err != nil || !info.IsDir() {
		return nil
	}
	sourceAbs, err := filepath.Abs(source)
	if err != nil {
		return nil
	}
	outputAbs, err := filepath.Abs(output)
	if err != nil {
		return nil
	}
	relative, err := filepath.Rel(sourceAbs, outputAbs)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil
	}
	return []string{filepath.ToSlash(relative)}
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

func nestedSkillFiles(a skil.Artifact) []string {
	var paths []string
	for _, f := range a.Files {
		path := filepath.ToSlash(f.Path)
		if strings.EqualFold(filepath.Base(path), "SKILL.md") && filepath.Dir(path) != "." {
			paths = append(paths, path)
		}
	}
	return paths
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
	rules := append(analyzer.BuiltinRules(), lint.Rules()...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}
