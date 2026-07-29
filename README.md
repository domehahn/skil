# skil

`skil` is an open, vendor-neutral security, verification, and assurance
framework for AI agent skills.

AI skills combine natural-language instructions, executable code, tools,
permissions, dependencies, and remote systems. Reviewing only their prompt or
validating only their schema is insufficient. `skil` keeps six activities
separate and connects them with digest-bound evidence:

```text
contract ─┐
analysis ─┼─> verification ─> policy ─> evidence ─> attestation
eval ─────┘
```

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
required. The `yara` executable is optional unless `--yara-rules` or
`--yara-builtin` is used.

```bash
go install github.com/domehahn/skil/cmd/skil@latest

skil validate ./my-skill
skil scan ./my-skill --static-only
skil scan ./my-skill --osv
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
  a per-analyzer/per-file inspection ledger with a completeness gate
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

A non-root multi-stage container image can be built with `make docker-build`;
`make docker-smoke` verifies its CLI entrypoint.

See [architecture](docs/architecture.md), [native security capabilities](docs/native-capabilities.md),
[threat model](docs/threat-model.md), [known limitations](docs/security-scanning.md),
and the [release identity checklist](docs/release-identity-checklist.md).

## CI gate

```yaml
env:
  SKILL_DIR: path/to/skill
  SKIL_POLICY: path/to/reviewed-policy.yaml

- run: go install github.com/domehahn/skil/cmd/skil@latest
- run: skil validate "$SKILL_DIR"
- run: skil scan "$SKILL_DIR" --format sarif --output skil.sarif
- run: skil policy check "$SKILL_DIR" --policy "$SKIL_POLICY"
```

`validate` expects one concrete skill directory, not a repository root or a
directory containing multiple skills. Run it once per skill in a collection.
Create an initial policy with `skil policy init --output policy.yaml`, review it,
and check the reviewed policy into the repository before using it as a CI gate.

Exit codes are stable: `0` passed, `1` a security/policy gate failed, `2`
invalid input or configuration, and `3` an internal failure.

## Project status

This is the first complete, intentionally bounded release. Pattern, semantic,
and taint analysis can produce false positives and false negatives. OSV, YARA,
and semantic analysis are explicit opt-ins shared by scan, verification,
attestation, policy, and installation; static-only mode needs no network,
model, API key, or external scanner. The isolated runtime is an explicit
adapter protocol available only through a native isolation provider. It denies
network access and host writes. Real tool requests are derived, authorized,
executed, and recorded by the trusted host gateway; adapter-supplied audit
claims are rejected. The runtime fails closed when the platform boundary is
unavailable.
Remote registry resolution remains disabled; remote HTTPS artifact and Git
scanning is explicit and never part of the offline default. The coverage block
and inspection ledger make unavailable, unrequested, routed, and completed work
visible.
Tagged releases are built natively for Linux amd64 and macOS arm64, accompanied
by checksums and SPDX SBOMs, attested through GitHub OIDC, and immediately
verified by the release workflow.

Apache-2.0 licensed. Contributions and responsible security reports are welcome.
