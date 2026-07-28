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
required. The `yara` executable is optional unless `--yara-rules` is used.

```bash
go install github.com/domehahn/skil/cmd/skil@latest

skil validate ./my-skill
skil scan ./my-skill --static-only
skil scan ./my-skill --osv
skil scan ./my-skill --yara-rules rules/malware.yar
skil scan ./my-skill --semantic --semantic-model gpt-4.1-mini
skil scan ./my-skill --format sarif --output skil.sarif
skil verify ./my-skill
skil eval ./my-skill --runtime mock --runs 20
skil key generate --output signing-key.pem
skil package build ./my-skill --output my-skill.tgz
skil package sign my-skill.tgz --signing-key signing-key.pem \
  --output package-signature.json
skil attest my-skill.tgz --signing-key signing-key.pem --output attestation.json
skil provenance create my-skill.tgz --repository https://github.com/acme/skills \
  --commit "$GIT_COMMIT" --builder https://ci.example/builders/skills \
  --signing-key signing-key.pem --output provenance.json
skil policy check my-skill.tgz --policy .skil/install-policy.yaml \
  --package-signature package-signature.json --attestation attestation.json \
  --provenance provenance.json
skil install my-skill.tgz --destination .skills --lock agent-skills.lock \
  --policy .skil/install-policy.yaml --package-signature package-signature.json \
  --attestation attestation.json --provenance provenance.json
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
network calls. Remote artifact fetching is deliberately unavailable in v0.1 until a
DNS-rebinding-resistant fetch boundary is implemented.

## What v0.1 implements

- safe directory, file, ZIP, and TGZ loading with per-file manifests and SHA-256
- discovery of root and vendor skill layouts containing `SKILL.md`
- strict versioned YAML skill contracts
- contextual instruction rules and Tree-sitter Python AST analysis with import
  alias resolution, plus Shell/JavaScript/TypeScript analysis
- bounded intraprocedural taint analysis
- generic dependency pinning/typosquatting and reputation checks, plus opt-in
  OSV vulnerability lookup
- trusted-source YARA scanning with bundled miner and webshell rules
- tool-less, structured OpenAI-compatible semantic analysis with SSRF controls
- MCP wildcard and tool-description-poisoning checks
- Unicode bidi/invisible-character and suspicious Base64 checks
- stable findings, fingerprints, transparent scoring, coverage reporting
- declared-versus-observed verification and explainable policies
- visible baseline suppression, JSON, Markdown, terminal, and SARIF 2.1.0
- deterministic behavioral/adversarial eval contracts, a mock runtime, and an
  explicit no-shell process-adapter protocol with deadline/output bounds
- canonical package validation, deterministic TGZ creation, atomic local
  installation, and `agent-skills.lock`
- separately bound package/content digests, scanner-key-bound evidence with
  embedded verdict payloads, attestations, detached package signatures, and
  DSSE in-toto/SLSA Provenance v1 with Ed25519 verification
- fail-closed host capability enforcement for files, network, structured
  command argv, secrets, tools, MCP, confirmations, tool/network budgets, and
  deadlines; unsupported hard memory limits are rejected
- extension interfaces for analyzers, semantic/vulnerability/signing providers,
  agent runtimes, and external evidence importers

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md),
and [known limitations](docs/security-scanning.md).

## CI gate

```yaml
- run: go install github.com/domehahn/skil/cmd/skil@latest
- run: skil validate .
- run: skil scan . --format sarif --output skil.sarif
- run: skil policy check . --policy .skil/policy.yaml
```

Exit codes are stable: `0` passed, `1` a security/policy gate failed, `2`
invalid input or configuration, and `3` an internal failure.

## Project status

This is the first complete, intentionally bounded release. Pattern, semantic,
and taint analysis can produce false positives and false negatives. OSV, YARA,
and semantic analysis are explicit opt-ins; static-only mode needs no network,
model, API key, or external scanner. The process runtime is an explicit adapter
protocol, not an OS sandbox; remote Git/registry fetching and OS-level
sandboxing remain host or extension capabilities.
The coverage block always makes unavailable or unrequested work visible.

Apache-2.0 licensed. Contributions and responsible security reports are welcome.
