# skil

[![CI](https://github.com/domehahn/skil/actions/workflows/ci.yml/badge.svg)](https://github.com/domehahn/skil/actions/workflows/ci.yml)
[![Release](https://github.com/domehahn/skil/actions/workflows/release.yml/badge.svg)](https://github.com/domehahn/skil/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/domehahn/skil)](https://goreportcard.com/report/github.com/domehahn/skil)
[![Go Reference](https://pkg.go.dev/badge/github.com/domehahn/skil.svg)](https://pkg.go.dev/github.com/domehahn/skil)
[![Go Version](https://img.shields.io/github/go-mod/go-version/domehahn/skil)](https://github.com/domehahn/skil/blob/main/go.mod)
[![License](https://img.shields.io/github/license/domehahn/skil)](https://github.com/domehahn/skil/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/domehahn/skil)](https://github.com/domehahn/skil/releases)

`skil` (**Skill Inspector and Linter**) is an open, vendor-neutral security,
verification, and assurance framework for AI agent skills.

AI skills combine natural-language instructions, executable code, tools,
permissions, dependencies, and remote systems. Reviewing only their prompt or
validating only their schema is insufficient. `skil` keeps six activities
separate and connects them with digest-bound evidence:

```text
contract ─┐
analysis ─┼─> verification ─> policy ─> evidence ─> attestation
eval ─────┘
```

- **Linting** catches authoring, consistency, metadata, link, and declaration
  problems before the heavier security scan.
- **Validation** checks structural and semantic correctness.
- **Scanning** identifies potential security risks without running skill code.
- **Verification** compares declared and statically observed capabilities.
- **Evaluation** measures behavior in an explicit, controlled runtime.
- **Attestation** binds evidence to one exact artifact digest.
- **Policy** makes an explainable environment-specific decision.
- **Runtime enforcement** is exposed as a fail-closed host capability gateway;
  scan results alone do not claim to enforce operations.

## Quick start

Go 1.24 or newer and a C toolchain (for the official Tree-sitter bindings) are
required. The built-in malware pack is native Go and requires no host scanner.
The `yara` executable is needed only for external `--yara-rules` or
`--yara-rules-dir` sources.

```bash
go install github.com/domehahn/skil/cmd/skil@latest

skil lint ./my-skill
skil lint ./my-skill --strict --format sarif --output skil-lint.sarif
skil lint ./my-skill --profile publish
skil lint-all .agents/skills --workers 8 --profile portable --format json
skil validate ./my-skill
skil scan ./my-skill --static-only
skil scan ./my-skill --osv
skil scan ./my-skill --full
skil scan ./my-skill --compact
skil scan ./my-skill --yara-rules rules/malware.yar
skil scan ./my-skill --yara-rules-dir rules/custom
skil scan ./my-skill --yara-builtin
skil scan ./my-skill --semantic --semantic-model gpt-4.1-mini
skil scan ./my-skill --semantic --semantic-provider anthropic \
  --semantic-model claude-sonnet-4-5 --semantic-api-key-env ANTHROPIC_API_KEY
skil scan ./my-skill --semantic --semantic-provider bedrock \
  --semantic-model anthropic.claude-3-7-sonnet --semantic-region eu-central-1
skil scan ./my-skill --format sarif --output skil.sarif
skil scan-all .agents/skills --workers 8 --format json --output skil-collection.json
skil scan https://github.com/acme/skill.git --allow-remote
skil verify ./my-skill --osv --yara-rules rules/malware.yar
skil sbom ./my-skill --output my-skill.spdx.json
skil eval ./my-skill --runtime mock --runs 20
skil assure ./my-skill --runtime-command ./trusted-agent-adapter --runs 20
skil key generate --output signing-key.pem
skil package build ./my-skill --output my-skill.tgz
skil package sign my-skill.tgz --signing-key signing-key.pem \
  --output package-signature.json
skil attest my-skill.tgz --osv --yara-rules rules/malware.yar \
  --signing-key signing-key.pem --output attestation.json
skil provenance create my-skill.tgz --repository https://github.com/acme/skills \
  --commit "$GIT_COMMIT" --builder https://ci.example/builders/skills \
  --signing-key signing-key.pem --output provenance.json
skil policy check my-skill.tgz --policy .skil/install-policy.yaml \
  --package-signature package-signature.json --attestation attestation.json \
  --provenance provenance.json
skil install my-skill.tgz --destination .skills --lock agent-skills.lock \
  --policy .skil/install-policy.yaml --package-signature package-signature.json \
  --attestation attestation.json --provenance provenance.json
skil update my-skill.tgz --destination .skills --lock agent-skills.lock \
  --policy .skil/install-policy.yaml --package-signature package-signature.json \
  --attestation attestation.json --provenance provenance.json
skil uninstall my-skill --destination .skills --lock agent-skills.lock
```

Local development:

```bash
make test
make lint
make build
./bin/skil scan tests/fixtures/malicious-skill
./bin/skil scan examples/scanner-torture-skill --static-only # expected exit 1
```

## Secure defaults

Scanned content is untrusted data, never instructions. `scan` reads regular
files but never imports Python, invokes scripts, installs dependencies, starts
MCP servers, or runs build hooks. Archive loading rejects traversal, absolute
paths, symlinks, duplicates, case collisions, oversized files, excessive file
counts, and decompression bombs. Static scanning is local and has no hidden
network calls. Remote public HTTPS Git and ZIP/TGZ inputs require
`--allow-remote`. Archive downloads use a DNS-rebinding-resistant direct dial
boundary and reject private, credential-bearing, redirected, and oversized
sources. Git clones are shallow, non-interactive, skip submodules, disable
local/ext protocols, and pass through the same resource-bounded loader.

Directory inputs may contain a checked-in `.skilignore` with simple path or
`directory/**` patterns for generated artifacts. skil deliberately does not
reuse `.gitignore`: security-relevant files must not disappear from scans merely
because Git ignores them. Negated and parent-traversing patterns are rejected,
and `.skilignore` itself remains part of the artifact manifest.

## What v0.1 implements

- safe directory, file, ZIP, and TGZ loading with per-file manifests and SHA-256
- discovery of root and vendor skill layouts containing `SKILL.md`
- strict versioned YAML skill contracts
- contextual instruction rules and Tree-sitter AST analysis for Python,
  JavaScript, TypeScript/TSX, and Bash, including Python import-alias resolution
- provider-free authoring lint with strict, portable, and publish profiles,
  collection mode, stable rules, and Terminal/JSON/Markdown/SARIF output
- syntax-aware bounded taint analysis with multi-step alias propagation and
  sanitizer boundaries
- deterministic dependency inventory across common Go, Python, npm, Cargo,
  RubyGems, and Maven manifests/locks; pinning, typosquatting, reputation, and
  opt-in OSV vulnerability checks with bounded batches, an integrity-checked
  cache, explicit offline mode, and visible degraded fallback
- offline SPDX 2.3 SBOM generation for skill manifests and embedded Go binary
  modules, bound to the artifact or executable digest
- trusted-source YARA file/directory scanning plus an independently maintained,
  opt-in conservative built-in rule pack
- separate tool-less semantic security, intent, and quality passes with a
  constrained synthesis pass through OpenAI-compatible, NVIDIA-compatible,
  native Anthropic, Anthropic raw-predict proxy, or AWS Bedrock providers with
  SSRF controls and native SigV4 where applicable
- MCP wildcard, tool-description-poisoning, and mutable-tool-identity checks
- dedicated cloud-metadata, SSRF, container-control-plane, and peer-agent-state
  boundary controls
- Unicode bidi/invisible/tag-character, hostname-confusable, and suspicious
  Base64 checks, plus conservative Chinese/Japanese/Korean static controls
- stable findings, fingerprints, transparent scoring, coverage reporting, and
  a detailed terminal report plus compact mode, and a per-analyzer/per-file
  inspection ledger with a completeness gate
- declared-versus-observed verification and explainable policies
- visible exact and reviewed glob baseline suppression with audit reasons;
  JSON, Markdown, terminal, and SARIF 2.1.0 reports
- deterministic behavioral/adversarial eval contracts, a mock runtime, and an
  explicit no-shell, multi-step process-adapter protocol with deadline/output
  bounds and host-mediated tool execution
- canonical package validation, deterministic TGZ creation, digest-guarded
  install/update/uninstall lifecycle, and `agent-skills.lock`
- separately bound package/content digests, scanner-key-bound evidence with
  embedded verdict payloads, attestations, detached package signatures, and
  DSSE in-toto/SLSA Provenance v1 with Ed25519 verification
- fail-closed host capability enforcement for files, network, structured
  command argv, secrets, tools, MCP, confirmations, tool/network budgets, and
  deadlines; Linux hard data/heap limits use `prlimit`, Windows uses AppContainer
  plus a Job Object, and unsupported provider/platform combinations fail closed
- extension interfaces for analyzers, semantic/vulnerability/signing providers,
  agent runtimes, and external evidence importers
- bounded parallel, deterministic multi-skill collection scanning and a
  confined MCP scanner service over stdio or bearer-authenticated loopback HTTP
- a live differential test harness against an external AI-skill security
  scanner: an 86-property corpus of positive/negative fixtures with CI gates,
  an auto-generated control crosswalk, and a property-level feature-parity
  document showing zero properties detected only by the external scanner

A non-root multi-stage container image can be built with `make docker-build`;
`make docker-smoke` verifies its CLI entrypoint.

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | System design, pipeline, and extension interfaces |
| [Skill contract](docs/skill-contract.md) | Versioned skill format and validation |
| [Linting](docs/linting.md) | Authoring checks and profiles |
| [Native security capabilities](docs/native-capabilities.md) | Built-in analyzers and rules |
| [Security model](docs/security-model.md) | Threat assumptions and trust boundaries |
| [Threat model](docs/threat-model.md) | Assets, attack surface, and countermeasures |
| [Known limitations](docs/security-scanning.md) | Static-scanning scope and blind spots |
| [Verification](docs/verification.md) | Declared-vs-observed capability checks |
| [Policy](docs/policy.md) | Explainable install-time decisions |
| [Attestations](docs/attestations.md) | Digest-bound evidence and signatures |
| [Supply chain](docs/supply-chain.md) | SBOM, provenance, and dependency checks |
| [Semantic analysis](docs/semantic-analysis.md) | Provider-backed model passes |
| [External control crosswalk](docs/external-control-crosswalk.md) | Rule-ID mapping to external scanners |
| [External scanner feature parity](docs/external-scanner-feature-parity.md) | Differential harness results and rationale |
| [Release identity checklist](docs/release-identity-checklist.md) | Release hardening checklist |
| [Glossary](docs/glossary.md) | Terminology |

Additional deep-dive documents: [adversarial testing](docs/adversarial-testing.md),
[behavioral testing](docs/behavioral-testing.md),
[provider model](docs/provider-model.md),
[capabilities](docs/capabilities.md),
[extending analyzers](docs/extending-analyzers.md), and the
[security control matrix](docs/security-control-matrix.md).

## CI gate

```yaml
env:
  SKILL_DIR: path/to/skill
  SKIL_POLICY: path/to/reviewed-policy.yaml

- run: go install github.com/domehahn/skil/cmd/skil@latest
- run: skil lint "$SKILL_DIR" --profile strict
- run: skil validate "$SKILL_DIR"
- run: skil scan "$SKILL_DIR" --format sarif --output skil.sarif
- run: skil policy check "$SKILL_DIR" --policy "$SKIL_POLICY"
```

`validate` expects one concrete skill directory, not a repository root or a
directory containing multiple skills. Run it once per skill in a collection.
Create an initial policy with `skil policy init --output policy.yaml`, review it,
and check the reviewed policy into the repository before using it as a CI gate.

The repository's required CI additionally executes a positive, digest-bound
`skil assure` workflow on Linux, macOS, and Windows and retains each JSON proof.
Use `make test-linux-assurance` to reproduce the complete Linux CLI path
locally. Public HTTPS gateway and live OSV checks run separately so provider
failures remain attributable.

Exit codes are stable: `0` passed, `1` a security/policy gate failed, `2`
invalid input or configuration, and `3` an internal failure.

## Project status

This is the first complete, intentionally bounded release. Pattern, local
semantic, and taint analysis can produce false positives and false negatives.
The native built-in malware and local cross-file semantic analyzers run
offline. OSV, external YARA sources, and model-backed semantic analysis remain
explicit opt-ins shared by scan, verification, attestation, policy, and
installation; static-only mode needs no network, model, API key, or external
scanner. `skil assure` combines scan, contract verification, mandatory
behavioral/containment evaluation, native isolation, and host-gateway
enforcement into one digest-bound gate. The isolated runtime is an explicit
adapter protocol available only through a native isolation provider. It denies
direct network access and host writes. Real artifact reads, private-workspace
access, structured non-shell commands, and bounded public HTTPS requests are
derived, authorized, executed, and recorded by the trusted host gateway;
adapter-supplied audit claims are rejected. The runtime fails closed when the
platform boundary is unavailable.
Remote registry resolution remains disabled; remote HTTPS artifact and Git
scanning is explicit and never part of the offline default. The coverage block
and inspection ledger make unavailable, unrequested, routed, and completed work
visible.
Tagged releases are built natively for Linux amd64, macOS arm64, and Windows
amd64, accompanied by checksums and binary-derived SPDX SBOMs, attested through
GitHub OIDC, downloaded into the publication job, and verified again before
release creation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community guidelines. Report
security vulnerabilities privately per [SECURITY.md](SECURITY.md). Third-party
attributions are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Licensed under [Apache-2.0](LICENSE).
