# skil

[![CI](https://github.com/domehahn/skil/actions/workflows/ci.yml/badge.svg)](https://github.com/domehahn/skil/actions/workflows/ci.yml)
[![Release](https://github.com/domehahn/skil/actions/workflows/release.yml/badge.svg)](https://github.com/domehahn/skil/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/domehahn/skil)](https://goreportcard.com/report/github.com/domehahn/skil)
[![Go Reference](https://pkg.go.dev/badge/github.com/domehahn/skil.svg)](https://pkg.go.dev/github.com/domehahn/skil)
[![Go Version](https://img.shields.io/github/go-mod/go-version/domehahn/skil)](https://github.com/domehahn/skil/blob/main/go.mod)
[![License](https://img.shields.io/github/license/domehahn/skil)](https://github.com/domehahn/skil/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/domehahn/skil)](https://github.com/domehahn/skil/releases)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/domehahn/skil/badge)](https://scorecard.dev/viewer/?uri=github.com/domehahn/skil)

`skil` (**Skill Inspector and Linter**) is an open, vendor-neutral **Continuous Agentic Assurance, Security, Verification, Provenance, and Supply-Chain Governance Platform** for AI agent skills, MCP servers, and multi-agent workspaces.

AI skills combine natural-language instructions, executable code, tool grants, permissions, dependencies, model weights, and remote protocols. Reviewing only a prompt or validating only a JSON schema is insufficient. `skil` unifies the end-to-end lifecycle **`DETECT → VERIFY → DECIDE → ATTEST → ENFORCE`** with digest-bound evidence:

```text
contract ─┐
analysis ─┼─> assurance closure ─> verification ─> policy ─> attestation ─> enforcement receipt
eval ─────┘
```

- **Linting** catches authoring, consistency, metadata, link, and declaration problems before heavier security analysis.
- **Validation** checks structural and semantic contract correctness.
- **Scanning (`DETECT`)** identifies security risks across instructions, code ASTs, interprocedural taint flows, dependencies, models, binaries, and MCP configs without executing untrusted skill code.
- **Verification (`VERIFY`)** compares declared capabilities against statically observed and runtime-observed behaviors, validates rule effectiveness, and proves provider invocation integrity.
- **Evaluation (`VERIFY`)** measures behavioral and adversarial containment in an explicit, isolated runtime.
- **Policy & Trust (`DECIDE`)** produces explainable, environment-specific admission and trust decisions (`ALLOW`, `DENY`, `REVIEW`, `REASSESS`).
- **Attestation & Provenance (`ATTEST`)** binds security evidence, SBOMs, and SLSA v1 provenance to an exact immutable artifact digest via Ed25519 / DSSE.
- **Runtime Enforcement (`ENFORCE`)** mediates host capabilities fail-closed and verifies cryptographically bound execution receipts.

See [Assurance closure](docs/assurance-closure.md), [Continuous Agentic Assurance](docs/continuous-agentic-assurance.md), and the [competitive feature radar](docs/research/competitive-feature-radar.md).

---

## Table of Contents

1. [Installation & Setup](#1-installation--setup)
2. [What Can Be Scanned (Targets, Languages, Formats & Platforms)](#2-what-can-be-scanned-targets-languages-formats--platforms)
3. [Security Taxonomy Domains, Rule Groups & Assurance Categories](#3-security-taxonomy-domains-rule-groups--assurance-categories)
4. [Shared Analysis Flags Reference](#4-shared-analysis-flags-reference)
5. [CLI Command Reference by Category](#5-cli-command-reference-by-category)
   - [Category A: Authoring, Validation & Security Scanning](#category-a-authoring-validation--security-scanning)
   - [Category B: Verification, Behavioral Evaluation, Red-Teaming & Assurance](#category-b-verification-behavioral-evaluation-red-teaming--assurance)
   - [Category C: Continuous Assurance, Policy, Governance, Trust & Graphs](#category-c-continuous-assurance-policy-governance-trust--graphs)
   - [Category D: Signing, Attestation, Provenance, SBOM, Receipts & ZK Proofs](#category-d-signing-attestation-provenance-sbom-receipts--zk-proofs)
   - [Category E: Package Lifecycle, Registry Admission & Multi-Skill Composition](#category-e-package-lifecycle-registry-admission--multi-skill-composition)
   - [Category F: MCP Security, Local Discovery, Runtime Proxy, Telemetry & DevOps](#category-f-mcp-security-local-discovery-runtime-proxy-telemetry--devops)
6. [Secure Defaults & Exit Codes](#6-secure-defaults--exit-codes)
7. [Documentation Index](#7-documentation-index)

---

## 1. Installation & Setup

### System Prerequisites

- **Go 1.24+** and a **C toolchain** (`gcc` or `clang`, required for official Tree-sitter AST bindings).
- **Optional — YARA CLI (`yara`)**: Required only when passing external `--yara-rules` or `--yara-rules-dir`. The built-in malware pack (`--yara-builtin`) is native Go and requires no external binary.
- **Optional — Native OS Isolation**: Used by `skil eval --runtime isolated`, `skil assure`, and `skil compose assure`:
  - **Linux**: `bubblewrap` (`bwrap`), `util-linux`, and `prlimit` (`sudo apt-get install -y bubblewrap util-linux`).
  - **macOS**: Built-in `sandbox-exec` seatbelt profiles.
  - **Windows**: AppContainer + Windows Job Objects.

### Install via `go install`

```bash
go install github.com/domehahn/skil/cmd/skil@latest
skil version --format json
```

### Build from Source

```bash
git clone https://github.com/domehahn/skil.git
cd skil
make build          # Compiles ./bin/skil
make test           # Runs the full test suite
make lint           # Runs static analysis / vet
```

### Non-Root Container Image (Docker / OCI)

```bash
make docker-build   # Builds non-root multi-stage image skil:latest
make docker-smoke   # Verifies CLI entrypoint and non-root UID

docker run --rm -v "$PWD:/scan:ro" skil:latest scan /scan/my-skill --static-only
```

### GitHub Action & CI/CD Gate

Use the official GitHub Action (verifies release binary build attestations and uploads SARIF):

```yaml
- uses: domehahn/skil@v0.2.0
  with:
    path: path/to/skill
    version: v0.7.0
    upload-sarif: 'true'
    fail-on-findings: 'true'
    sarif-file: skil.sarif
```

Or install pre-commit / CI pipelines directly via the CLI:

```bash
skil hook install --workspace . --strict
skil ci init --workspace . --platform github --policy .skil/policy.yaml
```

---

## 2. What Can Be Scanned (Targets, Languages, Formats & Platforms)

`skil` inspects heterogeneous agent artifacts through a unified, resource-bounded loader with SHA-256 content and container ancestry tracking:

| Scan Target Category | Supported Formats, Files & Surfaces | What `skil` Inspects |
| --- | --- | --- |
| **Artifact Containers & Sources** | Local directories, single files, `.tgz` / `.tar.gz`, `.zip`, nested archives (`outer.zip!/inner.zip`), multi-skill collections, Go binaries, opt-in HTTPS URLs & Git repos (`--allow-remote`), transitive HTTPS links (`--transitive`) | Path traversal, symlinks, archive bombs, case collisions, duplicate entries, `.skilignore` rules, container parent SHA-256 ancestry, source-bound cache keys. |
| **Skill Contracts & Instructions** | `SKILL.md`, `skil.yaml`, `skill.yaml`, Markdown docs, YAML frontmatter, prompt templates | Effective post-expansion YAML frontmatter (anchors `&`, aliases `*`, merge keys `<<`, folded/literal multiline scalars), scoped `allowed-tools` grants (`Bash(git:*)`), direct/indirect prompt injection, guardrail bypass, undisclosed operations, scope drift, Unicode bidi/tag/invisible smuggling, CJK evasion patterns. |
| **Source Code & Interprocedural Taint** | **Python** (`.py`, `.pyw`, extensionless Python shebang scripts, `.pyc` PEP 552 bytecode), **Shell/Bash** (`.sh`, `.bash`, `.zsh`), **JavaScript/TypeScript** (`.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`), **Ruby** (`.rb`) | Tree-sitter AST analysis, Python import/callable alias resolution, lexical function-scoped taint tracking (`scope::var` isolation, helper return-value propagation, keyword-argument sink matching), encoded execution chains (Base64/Base32/Hex/OpenSSL piped to `sh`/`bash`/`python`/`pwsh`/`eval`), bulk environment harvesting (`env`, `os.environ`, `/proc/self/environ` to network sinks), `.pyc` source-hash tampering. |
| **Dependencies & Supply Chain** | **Go** (`go.mod`, `go.sum`), **Python** (`requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`), **npm/Node** (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`), **Cargo** (`Cargo.toml`, `Cargo.lock`), **RubyGems** (`Gemfile`, `Gemfile.lock`), **Maven** (`pom.xml`) | Unpinned dependencies, git hashes misused as version ranges, contradictory version constraints, typosquatting, abandoned/malicious packages, install-time hooks (`postinstall`, `setup.py`), live or cached OSV.dev CVEs (`--osv`), SPDX 2.3 and CycloneDX SBOM generation. |
| **AI Models, Binaries & Non-Code Assets** | Pickle (`.pkl`, `.pickle`), PyTorch (`.pt`, `.pth`, `.bin`), Keras (`.h5`, `.keras`), SafeTensors, ONNX, GGUF, WebAssembly (`.wasm`), native binaries (`.so`, `.dylib`, `.dll`, ELF, PE, Mach-O), SVG, PDF, Office macros, polyglot files | Dangerous Pickle opcodes (`REDUCE`, `GLOBAL`, `STACK_GLOBAL`), Keras `Lambda` layers, unsigned/unpinned model references, WASM host imports, SVG `<script>`, PDF JavaScript, Office macros, MIME/magic-byte mismatches, steganography/polyglots, bounded readable instruction projection from binary headers (`GIF89a`, `%PDF-`, `\x7fELF` marked as `PARTIAL` analyzability), YARA rules. |
| **MCP Servers & Registries** | `server.json`, `.mcp.json`, official MCP Registry v0.1 entries, live stdio/HTTP MCP servers | Wildcard permissions, tool-description poisoning, metadata rug pulls, mutable tool identities, credential harvesting parameters, token passthrough, SSRF fetch tools, `camelCase`/`snake_case` schema drift, wrapper binary resolution (`env`, `command`, `npx`, `uvx` classified as `BOUNDED_SET` / `RUNTIME_UNKNOWN`). |
| **Local Agent Workspaces & Runtimes** | Claude Code (`.claude/`, `.claude/settings.local.json`), Claude Desktop, Cursor (`.cursor/mcp.json`), VS Code (`.vscode/mcp.json`), GitHub Copilot (`.github/copilot/`), Codex (`.codex/config.toml`), OpenCode (`opencode.json`), Kiro (`.kiro/settings/mcp.json`), Gemini (`.gemini/settings.json`), Windsurf (`.windsurf/`), Continue (`.continue/`), local AI infra (Ollama, vLLM, LM Studio, TGI) | Automatic multi-agent workspace and home-directory discovery (`skil discover`), coverage state tracking (`COMPLETE`, `PARTIAL`, `UNSUPPORTED`, `FAILED`), trust boundary separation between user-owned and repository-controlled configs. |

---

## 3. Security Taxonomy Domains, Rule Groups & Assurance Categories

### 3.1 The 17 Security Taxonomy Domains (`--domain` / `--list-domains`)

Every analyzer and rule in `skil` maps to one of 17 canonical security taxonomy domains. You can filter any scan using `--domain <domain-id>` (comma-separated) or list all active domains via `skil scan --list-domains`:

| Domain ID (`--domain`) | Title | Subdomains Covered | Representative Control & Rule IDs |
| --- | --- | --- | --- |
| `instruction` | **Instruction Security** | `prompt-injection`, `role-manipulation`, `guardrail-bypass`, `prompt-leakage`, `behavioral-steering` | `INSTR-001..009` (`SKIL-PI-001..003`, `SKIL-INTENT-REFUSAL`, `SKIL-INTENT-GUARDRAIL`, `SKIL-INTENT-UNDISCLOSED-OPERATION`) |
| `skill` | **Agentic Skill Security** | `trigger`, `scope`, `memory`, `persistence`, `output` | `SKILL-001..008` (`SKIL-INTENT-SCOPE`, `SKIL-BOUNDARY-PERSISTENCE`, `SKIL-OUTPUT-EXECUTION`, `SKIL-AGENT-SELF-MODIFY`, `SKIL-AGENCY-TOOLS`) |
| `tool-capability` | **Tool & Capability Security** | `least-privilege`, `tool-misuse`, `approval`, `capability-contracts` | `TOOL-001..006` (`SKIL-CAP-001`, `SKIL-CAP-DECLARATION-MISSING`, `SKIL-AGENCY-APPROVAL`) |
| `mcp` | **MCP Security** | `metadata`, `tool-poisoning`, `permissions`, `server-security`, `rug-pull` | `MCP-001..011` (`SKIL-MCP-001..011`) |
| `code` | **Code Security** | `ast`, `taint`, `dynamic-execution`, `obfuscation` | `CODE-001..015` (`SKIL-SH-001..002`, `SKIL-PY-001..004`, `SKIL-TAINT-*`, `SKIL-EXEC-ENCODED-CHAIN`, `SKIL-EXFIL-ENV-DUMP`, `SKIL-OBF-001`, `SKIL-UNI-001..003`) |
| `model` | **Model Security** | `unsafe-serialization`, `provenance`, `typosquatting`, `backdoors`, `drift` | `MODEL-001..012` (`SKIL-MODEL-PICKLE-001..003`, `SKIL-MODEL-KERAS-001`, `SKIL-MODEL-FORMAT-POLICY`, `SKIL-MODEL-REMOTE-CODE`, `SKIL-MODEL-UNPINNED`) |
| `data-dataset` | **Data / Dataset Security** | `poisoning`, `hidden-instructions`, `pii`, `provenance`, `license` | `DATA-001..008` (`SKIL-DATA-PURPOSE-VIOLATION`, `SKIL-DATA-RETENTION-UNBOUNDED`, `SKIL-DATA-OVERBROAD-COLLECTION`) |
| `rag-context` | **RAG / Context Security** | `indirect-injection`, `document-provenance`, `source-trust`, `cross-tenant`, `context-poisoning`, `privileged-mixing` | `RAG-001..006` (`SKIL-PI-002`) |
| `supply-chain` | **Supply Chain Security** | `dependencies`, `models`, `registries`, `build`, `provenance`, `artifacts` | `SC-001..011` (`SKIL-DEP-001..002`, `SKIL-DEP-VULN`, `SKIL-DEP-ABANDONED`, `SKIL-DEP-MALICIOUS`, `SKIL-BUILD-INSTALL-HOOK`, `SKIL-BUILD-REMOTE-EXEC`) |
| `identity-auth` | **Identity & Authorization** | `static-credentials`, `excessive-scope`, `role-assumption`, `impersonation`, `token-forwarding`, `cross-tenant` | `ID-001..012` (`SKIL-SECRET-HARDCODED`, `SKIL-SECRET-PRIVATE-KEY`, `SKIL-ID-LONG-LIVED-TOKEN`, `SKIL-ID-TOKEN-FORWARDING`, `SKIL-AUTH-*`) |
| `multi-agent` | **Multi-Agent / A2A Security** | `identity-spoofing`, `delegation-escalation`, `untrusted-output`, `circular-delegation`, `cross-tenant` | `A2A-001..005` (`SKIL-COMPOSE-*`) |
| `runtime-infra` | **Runtime & Infrastructure** | `container-escape`, `kubernetes`, `cloud-metadata`, `iam`, `network-namespace` | `RUNTIME-001..009` (`SKIL-BOUNDARY-CONTAINER-ESCAPE`, `SKIL-BOUNDARY-CONTAINER`, `SKIL-BOUNDARY-METADATA`, `SKIL-BOUNDARY-PEER-SKILL`, `SKIL-BOUNDARY-AGENT-STATE`, `SKIL-BOUNDARY-MCP-CONFIG`) |
| `network-lateral` | **Network & Lateral Movement** | `ssrf`, `c2`, `suspicious-egress`, `service-discovery`, `lateral-movement` | `NET-001..008` (`SKIL-NET-001`, `SKIL-C2-001`, `SKIL-C2-WEBSOCKET`, `SKIL-LAT-001`, `SKIL-EX-001`) |
| `asset-malware` | **Asset / Binary / Malware** | `active-content`, `embedded-binaries`, `polyglots`, `malware` | `ASSET-001..006` (`SKIL-ASSET-SVG-SCRIPT`, `SKIL-ASSET-PDF-JAVASCRIPT`, `SKIL-ASSET-OFFICE-MACRO`, `SKIL-ASSET-FILE-TYPE-MISMATCH`, `SKIL-ASSET-WASM-IMPORT`, `SKIL-ASSET-BINARY-INSTRUCTION`, `SKIL-YARA-*`) |
| `behavioral` | **Behavioral Security** | `hidden-triggers`, `adversarial-eval`, `tool-loops`, `runtime-observation` | `BEH-001..006` (`SKIL-INTENT-IMPLEMENTATION`, `SKIL-INTENT-DESCRIPTION`) |
| `audit-evidence` | **Audit / Evidence Security** | `evidence-integrity`, `audit-integrity`, `telemetry-security`, `scanner-bypass` | `AUDIT-001..004` |
| `policy-enforcement` | **Policy & Enforcement** | `domain-policy`, `verdict`, `enforcement-gate`, `compliance` | `POLICY-001..004` |

### 3.2 Rule Family Prefixes (`skil rules list` / `skil rules show <id>`)

| Rule Prefix | Category | Description |
| --- | --- | --- |
| `SKIL-PI-*` | Prompt Injection | Direct, indirect/RAG, and instruction-override prompt injection controls. |
| `SKIL-INTENT-*` | Semantic & Intent | Anti-refusal, guardrail suspension, undisclosed operations, scope violations, and description-vs-implementation divergence. |
| `SKIL-SH-*` | Shell / Bash Security | Dynamic shell evaluation, remote script piping (`curl \| sh`), privilege escalation. |
| `SKIL-PY-*` | Python AST & Bytecode | Subprocess execution, dynamic import manipulation, AST/eval injection, `.pyc` header tampering. |
| `SKIL-JS-*` / `SKIL-RB-*` | JS / TS / Ruby AST | `child_process`, dynamic `eval`/`Function`, Ruby `Kernel.system`/`eval`/backticks. |
| `SKIL-TAINT-*` | Interprocedural Taint | Source-to-sink dataflows into network egress (`NETWORK`), command execution (`EXECUTION`), file writes (`FILESYSTEM-WRITE`), and logs (`LOG`). |
| `SKIL-EXEC-*` / `SKIL-EXFIL-*` | Encoded Chains & Exfil | Multi-stage Base64/Base32/Hex/OpenSSL decode-and-execute chains (`SKIL-EXEC-ENCODED-CHAIN`) and bulk environment dumps (`SKIL-EXFIL-ENV-DUMP`). |
| `SKIL-SEC-*` / `SKIL-SECRET-*` | Secrets & Credentials | Hardcoded API keys, private keys, connection strings, and sensitive environment harvesting. |
| `SKIL-OBF-*` / `SKIL-UNI-*` | Obfuscation & Unicode | High-entropy/XOR payloads, bidirectional overrides, zero-width/tag smuggling, IDN homograph hostnames. |
| `SKIL-MCP-*` | MCP Protocol & Tools | Wildcards, tool poisoning, mutable identities, credential parameters, rug pulls, token passthrough, OAuth scopes. |
| `SKIL-DEP-*` / `SKIL-BUILD-*` | Dependency & Build | Unpinned versions, typosquatting, OSV vulnerabilities, abandoned/malicious packages, install hooks. |
| `SKIL-MODEL-*` | AI Model Integrity | Unsafe Pickle opcodes, Keras Lambda layers, unpinned/mutable HuggingFace refs, unsigned models, custom loaders. |
| `SKIL-ASSET-*` | Binary & Document Assets | Active SVG/PDF/Office scripts, polyglot MIME mismatches, WASM host imports, binary embedded instructions (`SKIL-ASSET-BINARY-INSTRUCTION`). |
| `SKIL-BOUNDARY-*` | Host & Cloud Boundaries | Cloud metadata (`169.254.169.254`), Docker socket/container escape, peer skill tampering, agent/MCP config modification, persistence. |
| `SKIL-NET-*` / `SKIL-C2-*` / `SKIL-LAT-*` | Network & Lateral | SSRF, reverse shells / C2 channels, suspicious WebSockets, SSH pivoting, data exfiltration. |
| `SKIL-YARA-*` | Malware Signatures | Built-in native Go malware signatures and external YARA rule matches. |
| `SKIL-LINT-*` | Authoring & Quality Lint | Frontmatter syntax, naming conventions, broken links, missing examples, portability, and publish-readiness rules. |

### 3.3 Canonical Severities, Conformance Profiles & External Crosswalks

- **Canonical Severities**: `CRITICAL` (rank 4), `HIGH` (rank 3), `UNKNOWN` (conservatively ranked at `HIGH` = 3, never silently downgraded to `LOW`), `MEDIUM` (rank 2), `LOW` (rank 1), `INFO` (rank 0).
- **ASPS Conformance Profiles (`skil conform --profile <name>`)**: `core`, `identity`, `multi-agent`, `supply-chain`, `mcp`, `privacy`, `resilience`, `audit`.
- **External Framework Crosswalks (`2026.10.1`)**: Automated mapping to **OWASP Top 10 for LLM Applications (`LLM01`–`LLM10`)**, **OWASP Agentic Security Initiative (`ASI01`–`ASI10`)**, **MITRE ATLAS (`AML.T*`)**, and **NIST AI RMF**.

---

## 4. Shared Analysis Flags Reference

The following flags are shared across `scan`, `scan-all`, `verify`, `assure`, `attest`, `policy check`, `policy init`, `install`, `update`, and `compose`:

| Flag | Type & Default | Description | Example |
| --- | --- | --- | --- |
| `--full` | `bool` (`false`) | Enables online OSV dependency queries (`--osv`) and the native built-in malware signature pack (`--yara-builtin`). Model semantic analysis remains explicit. | `skil scan ./my-skill --full` |
| `--static-only` | `bool` (`false`) | Explicitly disables all external semantic model providers. Mutually exclusive with `--semantic`. | `skil scan ./my-skill --static-only` |
| `--osv` | `bool` (`false`) | Queries `osv.dev` for known vulnerabilities in pinned dependencies across Go, PyPI, npm, Cargo, RubyGems, and Maven. | `skil scan ./my-skill --osv` |
| `--osv-cache` | `string` (`""`) | Path to an integrity-checked local JSON cache file for OSV responses. | `skil scan ./my-skill --osv --osv-cache .skil/osv-cache.json` |
| `--osv-offline` | `bool` (`false`) | Uses only the local `--osv-cache` without making network calls. Required when combining `--osv` with `--airgap`. | `skil scan ./my-skill --osv --osv-offline --osv-cache .skil/osv-cache.json` |
| `--osv-cache-ttl` | `duration` (`1h`) | Freshness window for cached OSV vulnerability entries. | `skil scan ./my-skill --osv --osv-cache .skil/osv.json --osv-cache-ttl 24h` |
| `--yara-builtin` | `bool` (`false`) | Scans files with `skil`'s built-in native Go malware signature pack (no external `yara` binary needed). | `skil scan ./my-skill --yara-builtin` |
| `--yara-rules` | `string` (`""`) | Path to a trusted external `.yar` / `.yara` source rules file (requires `yara` CLI). | `skil scan ./my-skill --yara-rules rules/malware.yar` |
| `--yara-rules-dir` | `string` (`""`) | Path to a flat directory of trusted `.yar` / `.yara` files. | `skil scan ./my-skill --yara-rules-dir rules/custom` |
| `--yara-binary` | `string` (`"yara"`) | Path or name of the external YARA executable. | `skil scan ./my-skill --yara-rules rules/malware.yar --yara-binary /usr/local/bin/yara` |
| `--semantic` | `bool` (`false`) | Enables tool-less LLM semantic security, intent, quality, policy, and synthesis passes. Requires `--semantic-model`. | `skil scan ./my-skill --semantic --semantic-model gpt-4.1-mini` |
| `--semantic-provider` | `string` (`"openai-compatible"`) | Semantic provider backend: `openai-compatible`, `nvidia`, `anthropic`, `anthropic-proxy`, or `bedrock`. | `skil scan ./my-skill --semantic --semantic-provider anthropic --semantic-model claude-sonnet-4-5` |
| `--semantic-endpoint` | `string` (`"https://api.openai.com/v1/chat/completions"`) | Custom HTTPS endpoint (or local endpoint when combined with `--semantic-allow-private`). | `skil scan ./my-skill --semantic --semantic-model llama3 --semantic-endpoint http://127.0.0.1:11434/v1/chat/completions --semantic-allow-private` |
| `--semantic-model` | `string` (`""`) | Model identifier for the chosen semantic provider. | `--semantic-model gpt-4.1-mini` |
| `--semantic-api-key-env` | `string` (`"OPENAI_API_KEY"`) | Environment variable name holding the provider API key (defaults to `NVIDIA_INFERENCE_KEY` for `nvidia` and `ANTHROPIC_PROXY_API_KEY` for `anthropic-proxy`). | `--semantic-api-key-env ANTHROPIC_API_KEY` |
| `--semantic-allow-private` | `bool` (`false`) | Permits connecting to a private/loopback semantic endpoint (required for `--semantic` under `--airgap`). | `--semantic-allow-private` |
| `--semantic-region` | `string` (`"us-west-2"`) | AWS region when `--semantic-provider bedrock` is selected. | `--semantic-provider bedrock --semantic-region eu-central-1` |
| `--semantic-api-version` | `string` (`""`) | Optional API version header for `anthropic-proxy`. | `--semantic-api-version 2023-06-01` |
| `--semantic-validation` | `string` (`"review"`) | Output validation strictness: `review` (downgrades verdict to review on malformed output) or `strict` (hard-fails scan). | `--semantic-validation strict` |
| `--semantic-runs` | `int` (`1`) | Number of independent semantic model passes per request; findings are kept by majority consensus. | `--semantic --semantic-model gpt-4.1-mini --semantic-runs 3` |
| `--require-complete` | `bool` (`false`) | Fails the security gate (`exit 1`) unless 100% of applicable inspection work items completed. | `skil scan ./my-skill --require-complete` |
| `--fail-on-incomplete` | `bool` (`false`) | Fails the security gate (`exit 1`) if any analysis budget (raw/expanded bytes, findings, events, wall time) was exceeded. | `skil scan ./my-skill --fail-on-incomplete` |
| `--allow-remote` | `bool` (`false`) | Explicitly permits fetching a public HTTPS `.tgz`/`.zip` archive or shallow-cloning a public HTTPS Git repository. | `skil scan https://github.com/acme/skill.git --allow-remote` |
| `--airgap` | `bool` (`false`) | Hard-fails before any work starts if any network-capable flag (`--full`, online `--osv`, public `--semantic`, `--allow-remote`, `--transitive`) is enabled. | `skil scan ./my-skill --airgap --yara-builtin` |
| `--dependency-reputation` | `string` (`""`) | Path to a trusted offline package-reputation JSON file merged with the built-in reputation catalog. | `skil scan ./my-skill --dependency-reputation .skil/reputation.json` |
| `--domain` | `string` (`""`) | Comma-separated list of taxonomy domain IDs to run (e.g., `code,mcp,supply-chain`). | `skil scan ./my-skill --domain code,mcp` |
| `--list-domains` | `bool` (`false`) | Prints all registered taxonomy domain IDs and exits with `0`. | `skil scan --list-domains` |

---

## 5. CLI Command Reference by Category

### Category A: Authoring, Validation & Security Scanning

#### `skil validate <skill>`
Validates a single skill directory or archive against the versioned `skil.yaml` / `SKILL.md` structural and authoring contract.
- `--format <terminal|json|markdown>` (default: `terminal`): Output format.
```bash
skil validate ./my-skill
skil validate ./my-skill --format json
```

#### `skil lint <skill>`
Runs provider-free authoring, metadata, link, and declaration checks on a single skill.
- `--profile <default|strict|portable|publish>` (default: `default`): Lint strictness profile (`portable` checks cross-agent compatibility; `publish` enforces registry-ready documentation and metadata).
- `--strict` (default: `false`): Shorthand to promote warnings to gate failures (`exit 1`).
- `--format <terminal|json|markdown|sarif>` (default: `terminal`): Report format.
- `--output <file>` (default: stdout): Write report to a file (automatically excluded from self-scanning).
```bash
skil lint ./my-skill --profile publish
skil lint ./my-skill --strict --format sarif --output skil-lint.sarif
```

#### `skil lint-all <collection>`
Discovers all skills containing `SKILL.md` under `<collection>` and lints them in parallel.
- `--profile <default|strict|portable|publish>` (default: `default`): Lint profile applied to each skill.
- `--workers <1..64>` (default: `1`): Number of concurrent lint workers.
- `--format <terminal|json|markdown>` (default: `terminal`): Collection report format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil lint-all .agents/skills --workers 8 --profile portable --format json --output lint-collection.json
```

#### `skil scan <skill>`
Runs static, AST, taint, dependency, asset, MCP, and optional YARA/OSV/semantic security analysis on a skill directory, file, archive, or remote repository.
- Accepts all **[Shared Analysis Flags](#4-shared-analysis-flags-reference)**.
- `--format <terminal|json|markdown|sarif|interactive-html>` (default: `terminal`): Report output format.
- `--compact` (default: `false`): Emits one-line-per-finding compact terminal output.
- `--interactive` (default: `false`): Generates a standalone interactive HTML workbench report.
- `--output <file>` (default: stdout): Output file path.
- `--baseline <file>` (default: `""`): Path to a signed/integrity-sealed baseline YAML file to suppress reviewed findings.
- `--show-suppressed` (default: `true`): Include suppressed findings in the report (`--show-suppressed=false` hides them).
- `--transitive` (default: `false`): Recursively fetches and scans external HTTPS references linked from the skill.
- `--transitive-depth <int>` (default: `1`): Maximum hop depth for transitive reference scanning.
- `--transitive-allow-prefix <p1,p2>` (default: `""`): Comma-separated URL prefixes permitted for transitive scanning.
- `--transitive-deny-prefix <p1,p2>` (default: `""`): Comma-separated URL prefixes blocked from transitive scanning (overrides allow).
```bash
skil scan ./my-skill --static-only
skil scan ./my-skill --full --require-complete --fail-on-incomplete --format sarif --output skil.sarif
skil scan ./my-skill --transitive --transitive-depth 2 --transitive-allow-prefix https://github.com/acme/
skil scan ./my-skill --interactive --output scan-workbench.html
```

#### `skil scan-all <collection>`
Discovers and scans every skill in a multi-skill directory or remote repository in parallel.
- Accepts all **[Shared Analysis Flags](#4-shared-analysis-flags-reference)**.
- `--workers <1..64>` (default: `1`): Parallel skill scan workers.
- `--baseline <file>` (default: `""`): Baseline file applied across the collection.
- `--format <terminal|json|markdown>` (default: `terminal`): Collection summary format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil scan-all .agents/skills --workers 8 --yara-builtin --format json --output skil-collection.json
```

#### `skil explain <scan.json>`
Produces an operator-oriented explanation of findings, assurance closure state, blockers, and remediation steps from a scan JSON file.
- `--format <terminal|json>` (default: `terminal`): Explanation output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil scan ./my-skill --format json --output scan.json
skil explain scan.json --format terminal
```

#### `skil completeness <skill>`
Evaluates and reports the Assurance Completeness Model, per-file inspection ledger, resolution evidence (`EXACT`, `BOUNDED_SET`, `PARTIAL`, `RUNTIME_UNKNOWN`), and analyzability class (`FULL`, `PARTIAL`, `OPAQUE`).
- `--format <terminal|json|yaml>` (default: `terminal`): Output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil completeness ./my-skill --format terminal
skil completeness ./my-skill --format json --output completeness.json
```

#### `skil inspect <skill>`
Loads an artifact and outputs its complete file manifest, SHA-256 digests, container ancestry, discovered `SKILL.md`, and parsed contract JSON.
```bash
skil inspect ./my-skill
```

#### `skil rules [list | show <rule-id>]`
Lists all built-in security and lint rules or displays the full JSON specification and metadata for one rule ID.
```bash
skil rules list
skil rules show SKIL-EXEC-ENCODED-CHAIN
```

#### `skil analyzers [list]`
Outputs JSON metadata for all registered analyzers, their supported domains, and capabilities.
```bash
skil analyzers list
```

#### `skil capabilities`
Outputs a JSON manifest of host and scanner capabilities (available analyzers, providers, native OS isolation availability, external `yara` presence, supported formats).
```bash
skil capabilities
```

#### `skil stego scan <skill>`
Scans binary and media assets in a skill for steganographic payloads, polyglot headers, high-entropy appended data, and hidden instructions.
- `--format <terminal|json>` (default: `terminal`): Output format.
```bash
skil stego scan ./my-skill --format json
```

---

### Category B: Verification, Behavioral Evaluation, Red-Teaming & Assurance

#### `skil verify <skill>`
Compares capabilities declared in `skil.yaml` against capabilities statically observed in code, instructions, and dependencies.
- Accepts all **[Shared Analysis Flags](#4-shared-analysis-flags-reference)**.
- `--format <terminal|json>` (default: `terminal`): Output format.
```bash
skil verify ./my-skill --osv --yara-builtin --format json
```

#### `skil contract verify <skill>`
Verifies that a skill's runtime behavior and observed capabilities strictly satisfy its formal `skil.yaml` contract.
- `--format <terminal|json>` (default: `terminal`): Output format.
```bash
skil contract verify ./my-skill --format terminal
```

#### `skil eval <skill>` & `skil eval run <skill>`
Executes deterministic behavioral or adversarial test suites against a skill in a `mock` or native OS `isolated` runtime.
- `skil eval <skill>`:
  - `--test <file>` (default: auto-discovered `*eval*.yaml` / `*behavior*.yaml`): Path to behavioral/adversarial eval YAML (`eval-v1.schema.json`).
  - `--runtime <mock|isolated>` (default: `mock`): Execution runtime (`isolated` enforces OS sandbox + host capability gateway).
  - `--runtime-command <executable>` (default: `""`): Adapter executable required when `--runtime isolated`.
  - `--runtime-args <a,b>` (default: `""`): Comma-separated arguments passed to `--runtime-command`.
  - `--max-output-bytes <int64>` (default: `1048576`): Maximum stdout bytes captured per run.
  - `--runs <int>` (default: `1`): Number of evaluation iterations.
  - `--output <file>` (default: stdout): Write `EvalResult` JSON to file.
- `skil eval run <skill>`:
  - `--suite <file>` (default: built-in suite): Custom evaluation suite JSON/YAML.
  - `--format <terminal|json|yaml>` (default: `terminal`): Output format.
  - `--output <file>` (default: stdout): Output file path.
```bash
skil eval ./my-skill --runtime mock --runs 20 --output eval-result.json
skil eval ./my-skill --runtime isolated --runtime-command ./bin/assurance-adapter --runs 5
skil eval run ./my-skill --format json
```

#### `skil assure <skill>`
Executes the complete digest-bound assurance gate: static/semantic scan + declared-vs-observed contract verification + mandatory isolated behavioral & containment evaluation + host-gateway enforcement proof.
- Accepts all **[Shared Analysis Flags](#4-shared-analysis-flags-reference)**.
- `--runtime-command <executable>` (**required**): Path to the isolated agent runtime adapter executable.
- `--runtime-args <a,b>` (default: `""`): Comma-separated adapter arguments.
- `--test <file>` (default: auto-discovered): Behavioral/adversarial eval YAML with `containment.required: true`.
- `--max-output-bytes <int64>` (default: `1048576`): Maximum stdout bytes per run.
- `--runs <int>` (default: `1`): Number of isolated assurance runs.
- `--format <terminal|json>` (default: `terminal`): Output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil assure ./my-skill --runtime-command ./bin/assurance-adapter --runs 10 --format json --output assurance-proof.json
```

#### `skil probe <skill>` (alias: `skil redteam <skill>`)
Runs automated adversarial red-teaming probes against a skill to measure exploitability across injection, obfuscation, exfiltration, and tool-abuse payloads.
- `--payloads <CAT1,CAT2>` (default: all categories): Comma-separated attack categories (e.g., `INDIRECT_INJECTION,OBFUSCATION_ENCODING`).
- `--format <terminal|json|yaml>` (default: `terminal`): Output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil probe ./my-skill --payloads INDIRECT_INJECTION,OBFUSCATION_ENCODING --format json --output probe-report.json
```

#### `skil sandbox run <skill>`
Executes a skill inside a honeypot/sandbox environment to observe attempted filesystem, network, and process actions.
- `--workspace <dir>` (default: `"."`): Workspace root directory.
- `--format <terminal|json>` (default: `terminal`): Output format.
```bash
skil sandbox run ./my-skill --workspace . --format json
```

---

### Category C: Continuous Assurance, Policy, Governance, Trust & Graphs

#### `skil continuous check <skill>`
Evaluates continuous assurance state across time, detecting artifact digest drift, policy digest changes, expired evidence, and subagent/session state changes.
- `--policy <file>` (**required**): Policy YAML file.
- `--state <file>` (**required**): Persistent assurance state JSON file (created/updated across runs).
- `--format <terminal|json>` (default: `terminal`): Output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil continuous check ./my-skill --policy .skil/policy.yaml --state .skil/assurance-state.json --format json
```

#### `skil policy init`
Creates a new installation/admission policy YAML file (or synthesizes a least-privilege policy from a scan trace).
- `--output <file>` (default: `".skil/policy.yaml"`): Destination policy path (created with `0600`, never overwrites existing files).
- `--from-trace <path>` (default: `""`): Synthesize policy rules from an existing scan JSON or skill directory.
- `--strict` (default: `false`): Enable strict closure and execution bounds in the synthesized policy.
- Accepts **[Shared Analysis Flags](#4-shared-analysis-flags-reference)** when `--from-trace` points to a skill directory.
```bash
skil policy init --output .skil/policy.yaml
skil policy init --from-trace ./my-skill --strict --output .skil/strict-policy.yaml
```

#### `skil policy check <skill>`
Evaluates a skill and its cryptographic evidence against an organization policy (`ALLOW` vs `DENY`).
- Accepts all **[Shared Analysis Flags](#4-shared-analysis-flags-reference)**.
- `--policy <file>` (**required**): Path to the policy YAML file.
- `--format <terminal|json>` (default: `terminal`): Output format.
- `--attestation <file>` (default: `""`): Signed scan attestation JSON/YAML.
- `--provenance <file>` (default: `""`): Signed SLSA provenance JSON/YAML.
- `--package-signature <file>` (default: `""`): Detached package signature JSON/YAML.
- `--evidence <f1,f2>` (default: `""`): Comma-separated signed external SARIF evidence bundles.
- `--eval-result <file>` (default: `""`): Behavioral/containment evaluation result JSON/YAML.
```bash
skil policy check ./my-skill.tgz --policy .skil/policy.yaml \
  --package-signature package-signature.json \
  --attestation attestation.json \
  --provenance provenance.json \
  --format json
```

#### `skil policy adapt`
Adapts an existing policy file using observed runtime execution trace logs.
- `--trace <file>` (**required**): Execution trace log JSON path.
- `--output <file>` (default: `".skil/policy.yaml"`): Output policy YAML path.
```bash
skil policy adapt --trace runtime-trace.json --output .skil/adapted-policy.yaml
```

#### `skil gate check`
Verifies a packaged artifact, its signed attestation, and a policy file as a standalone deployment/CI gate.
- `--artifact <path>` (**required**): Artifact directory or package archive.
- `--attestation <file>` (**required**): Signed attestation JSON file.
- `--policy <file>` (**required**): Policy YAML file.
- `--format <terminal|json>` (default: `terminal`): Output format.
```bash
skil gate check --artifact my-skill.tgz --attestation attestation.json --policy .skil/policy.yaml --format json
```

#### `skil baseline create <skill>`
Creates a subject-bound, occurrence-fingerprinted, SHA-256 integrity-sealed Baseline v3 YAML file from a complete scan (refuses incomplete or budget-exceeded scans and refuses symlink output paths).
- `--output <file>` (default: stdout): Destination baseline YAML file.
- `--approved-by <identity>` (default: `"unapproved"`): Approver identity recorded for auditability.
- `--reason <text>` (default: `"initial baseline; requires review"`): Audit reason recorded on each entry.
```bash
skil baseline create ./my-skill --approved-by "secops@example.com" --reason "Reviewed false positive in test fixture" --output .skil/baseline.yaml
```

#### `skil conform`
Evaluates `skil`'s built-in control coverage against the Agentic Security Property Specification (ASPS v1.0) profiles.
- `--profile <core|identity|multi-agent|supply-chain|mcp|privacy|resilience|audit>` (**required**): Conformance profile to evaluate.
- `--format <terminal|json>` (default: `terminal`): Output format.
```bash
skil conform --profile supply-chain --format json
```

#### `skil trust <skill>`
Computes a weighted 0–100 **Skill Trust Score**, Trust Level, and Registry Admission recommendation across Security, Quality, Evaluation Lift, Provenance/Signing, Permission Risk, and Catalog Duplicate Risk.
- `--catalog <file>` (default: `".skil/catalog.json"`): Registry catalog JSON used for duplicate/overlap scoring.
- `--format <terminal|json|sarif>` (default: `terminal`): Output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil trust ./my-skill --catalog .skil/catalog.json --format json --output trust-report.json
```

#### `skil card <skill>`
Generates a machine- and human-readable **Skill Card** summarizing identity, digest, trust score, declared vs. observed capabilities, permissions, and security posture.
- `--format <yaml|markdown|json>` (default: `yaml`): Output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil card ./my-skill --format markdown --output SKILL_CARD.md
```

#### `skil compare <base-skill> <target-skill>` (alias: `skil drift`)
Compares two versions of a skill and reports trust score delta, added permissions, capability drift, new security findings, and upgrade admission decision.
- `--format <terminal|json>` (default: `terminal`): Output format.
```bash
skil compare ./v1/my-skill ./v2/my-skill --format json
```

#### `skil optimize context <skill>`
Analyzes `SKILL.md` and bundled prompt assets for token bloat, redundant instructions, and context-window efficiency.
- `--format <terminal|json>` (default: `terminal`): Output format.
```bash
skil optimize context ./my-skill --format terminal
```

#### `skil graph capabilities <skill-paths...>` & `skil graph attack-path <skill-paths...>`
Builds a capability graph across one or more skills and detects cross-skill exfiltration and privilege-escalation attack paths.
- `--format <terminal|json>` (default: `terminal`): Output format.
```bash
skil graph capabilities ./skill-a ./skill-b --format json
skil graph attack-path ./skill-a ./skill-b --format terminal
```

---

### Category D: Signing, Attestation, Provenance, SBOM, Receipts & ZK Proofs

#### `skil key generate`
Generates a new Ed25519 signing keypair in PKCS#8 PEM format (created with mode `0600`, never overwrites existing files) and prints the public key and key ID JSON.
- `--output <file>` (**required**): Output path for the private key PEM file.
```bash
skil key generate --output signing-key.pem
```

#### `skil package build <skill>` & `skil package sign <skill.tgz>`
Builds a deterministic, reproducible `.tgz` skill package and signs a detached package statement binding both `package_sha256` and `content_manifest_sha256`.
- `skil package build <skill>`:
  - `--output <file>` (**required**): Path for the new `.tgz` package.
- `skil package sign <skill.tgz>`:
  - `--signing-key <key.pem>` (**required**): Ed25519 private key PEM file.
  - `--key-id <id>` (default: public-key fingerprint): Signer key ID.
  - `--output <file>` (**required**): Output file for the signed `PackageStatement` JSON.
```bash
skil package build ./my-skill --output my-skill.tgz
skil package sign my-skill.tgz --signing-key signing-key.pem --output package-signature.json
```

#### `skil attest <skill>`
Scans an artifact, attaches optional behavioral evaluation results, and emits a signed attestation bound to the exact subject digest.
- Accepts all **[Shared Analysis Flags](#4-shared-analysis-flags-reference)**.
- `--signing-key <key.pem>` (default: `""`): Ed25519 private key PEM file.
- `--key-id <id>` (default: public-key fingerprint): Signer key ID.
- `--signer <file|pkcs11|yubikey|hsm>` (default: `"file"`): Signing provider backend.
- `--slot <int>` (default: `0`): Hardware token slot index when using hardware signers.
- `--eval-result <file>` (default: `""`): Attach a behavioral `EvalResult` JSON/YAML verified against the same artifact digest.
- `--session-bound` (default: `false`): Bind prompt context, model parameters, and session memory digest into the attestation.
- `--output <file>` (default: stdout): Output file path.
```bash
skil attest my-skill.tgz --full --eval-result eval-result.json --signing-key signing-key.pem --output attestation.json
```

#### `skil provenance create <skill.tgz>`
Creates and signs an in-toto / SLSA v1 Provenance DSSE statement for a packaged archive.
- `--repository <url>` (**required**): Canonical source repository URL.
- `--commit <sha>` (**required**): Immutable source Git commit SHA.
- `--builder <id>` (**required**): Trusted builder URI/identity.
- `--signing-key <key.pem>` (**required**): Ed25519 private key PEM file.
- `--key-id <id>` (default: public-key fingerprint): Signer key ID.
- `--output <file>` (default: stdout): Output file path.
```bash
skil provenance create my-skill.tgz \
  --repository https://github.com/acme/skills \
  --commit 93d3daaad33fd216b2c7584e8d6704e67f9ad55b \
  --builder https://github.com/acme/skills/.github/workflows/release.yml \
  --signing-key signing-key.pem \
  --output provenance.json
```

#### `skil evidence sign <skill>`
Imports an external SARIF 2.1.0 report, verifies its subject digest binding against `<skill>`, and signs it as a `skil.EvidenceBundle`.
- `--sarif <file>` (**required**): SARIF 2.1.0 report path.
- `--signing-key <key.pem>` (**required**): Ed25519 private key PEM file.
- `--key-id <id>` (default: public-key fingerprint): Signer key ID.
- `--output <file>` (default: stdout): Output file path.
```bash
skil evidence sign ./my-skill --sarif external-report.sarif --signing-key signing-key.pem --output evidence-bundle.json
```

#### `skil sbom <skill-or-binary>`
Generates an offline Software Bill of Materials (SPDX 2.3 or CycloneDX) for a skill directory/archive or a compiled Go binary.
- `--format <spdx|cyclonedx>` (default: `spdx`): SBOM specification format.
- `--output <file>` (default: stdout): Output JSON file path.
```bash
skil sbom ./my-skill --format spdx --output my-skill.spdx.json
skil sbom ./my-skill --format cyclonedx --output my-skill.cdx.json
skil sbom ./bin/skil --output skil-binary.spdx.json
```

#### `skil receipt verify <receipt.json>`
Verifies a post-runtime execution receipt (`skrun-receipt-v1.schema.json`) against expected subject and policy digests and isolation requirements.
- `--subject <sha256:...>` (default: `""`): Expected artifact subject digest.
- `--policy <sha256:...>` (default: `""`): Expected policy digest.
- `--require-native-isolation` (default: `false`): Fail unless native OS isolation was active and enforced.
- `--format <terminal|json|yaml>` (default: `terminal`): Output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil receipt verify skrun-receipt.json --subject sha256:e3b0c44... --require-native-isolation --format json
```

#### `skil zk prove <skill>` & `skil zk verify <proof.json>`
Generates and verifies zero-knowledge compliance commitments proving a skill passed security controls without disclosing proprietary skill source code.
- `skil zk prove <skill> [--format terminal|json]`
- `skil zk verify <proof.json>`
```bash
skil zk prove ./my-skill --format json > zk-proof.json
skil zk verify zk-proof.json
```

#### `skil revoke add <digest-or-name>` & `skil revoke check <digest-or-name>`
Adds an artifact or skill identity to the local revocation registry or checks whether an artifact has been revoked.
- `--registry <file>` (default: `".skil/revocations.json"`): Path to the revocation registry JSON.
- `--reason <text>` (default: `"Revoked by security operator"`, on `add`): Revocation reason.
```bash
skil revoke add sha256:deadbeef... --registry .skil/revocations.json --reason "Compromised upstream publisher key"
skil revoke check sha256:deadbeef... --registry .skil/revocations.json
```

---

### Category E: Package Lifecycle, Registry Admission & Multi-Skill Composition

#### `skil install <skill.tgz>` & `skil update <skill.tgz>`
Verifies policy, detached package signature, signed scan attestation, and SLSA provenance, then atomically installs or updates the skill with automatic rollback and updates `agent-skills.lock`.
- Accepts all **[Shared Analysis Flags](#4-shared-analysis-flags-reference)**.
- `--destination <dir>` (**required**): Target installation directory.
- `--policy <file>` (**required**): Mandatory installation policy YAML.
- `--package-signature <file>` (**required**): Detached package signature JSON.
- `--attestation <file>` (**required**): Signed scan attestation JSON.
- `--provenance <file>` (**required**): Signed SLSA provenance JSON.
- `--evidence <f1,f2>` (default: `""`): Optional comma-separated signed external evidence bundles.
- `--expected-package-digest <sha256>` (default: `""`): Optional explicit package SHA-256 pin.
- `--lock <file>` (default: `"agent-skills.lock"`): Lockfile path.
```bash
skil install my-skill.tgz \
  --destination .skills \
  --lock agent-skills.lock \
  --policy .skil/install-policy.yaml \
  --package-signature package-signature.json \
  --attestation attestation.json \
  --provenance provenance.json
```

#### `skil uninstall <skill-name>`
Verifies that the installed skill directory matches its locked `content_manifest_sha256` (refusing to delete modified/untracked files), quarantines and removes it, and updates the lockfile.
- `--destination <dir>` (**required**): Installation root directory.
- `--lock <file>` (default: `"agent-skills.lock"`): Lockfile path.
```bash
skil uninstall my-skill --destination .skills --lock agent-skills.lock
```

#### `skil lock verify <skill.tgz>`
Verifies that a packaged archive matches the exact `package_sha256` and `content_manifest_sha256` recorded in `agent-skills.lock`.
- `--lock <file>` (default: `"agent-skills.lock"`): Lockfile path.
```bash
skil lock verify my-skill.tgz --lock agent-skills.lock
```

#### `skil registry <subcommand>`
Manages the Skill Registry Catalog, semantic deduplication, capability overlap detection, and registry admission gates:
- `skil registry index <directory> [--catalog .skil/catalog.json] [--namespace ns]`: Indexes all skills in `<directory>` into the catalog.
- `skil registry check <skill> [--catalog .skil/catalog.json] [--namespace ns] [--policy policy.yaml] [--fail-on reject|review|duplicate] [--format terminal|json|sarif]`: Evaluates candidate skill for security, quality, and duplication against the catalog.
- `skil registry list [--catalog .skil/catalog.json] [--namespace ns] [--domain domain] [--format terminal|json]`: Lists indexed catalog skills.
- `skil registry search <query> [--catalog .skil/catalog.json] [--top-k 5]`: Searches indexed skills by capability/keyword.
- `skil registry similar <skill> [--catalog .skil/catalog.json] [--top-k 5]`: Finds existing skills with overlapping capabilities or instructions.
- `skil registry compare <candidate> <existing> [--catalog .skil/catalog.json]`: Performs side-by-side duplicate and capability-improvement analysis.
```bash
skil registry index .agents/skills --catalog .skil/catalog.json --namespace platform
skil registry check ./candidate-skill --catalog .skil/catalog.json --fail-on duplicate --format json
skil registry similar ./candidate-skill --catalog .skil/catalog.json --top-k 5
```

#### `skil admission serve`
Starts a loopback HTTP Registry Admission Controller API that evaluates artifacts against a mandatory policy inside a confined root directory.
- `--listen <127.0.0.1:port>` (**required**): Loopback address and port.
- `--root <dir>` (**required**): Confined directory below which candidate artifacts must reside.
- `--policy <file>` (**required**): Admission policy YAML file.
- `--token-env <ENV>` (default: `"SKIL_ADMISSION_TOKEN"`): Environment variable holding the required HTTP Bearer token.
```bash
export SKIL_ADMISSION_TOKEN="$(openssl rand -hex 32)"
skil admission serve --listen 127.0.0.1:8443 --root /srv/skills --policy .skil/policy.yaml
```

#### `skil compose <collection>`, `skil compose taint <collection>` & `skil compose assure <collection>`
Analyzes multi-skill collections for toxic capability compositions (e.g., Skill A reads private credentials/files + Skill B has external network egress), cross-skill taint flows, and shared-workspace runtime containment.
- `skil compose <collection> [--format terminal|json] [--output file]` (plus **[Shared Analysis Flags](#4-shared-analysis-flags-reference)**)
- `skil compose taint <collection> [--format terminal|json] [--output file]`
- `skil compose assure <collection> --runtime-command <executable> [--runtime-args a,b] [--max-output-bytes N] [--format terminal|json] [--output file]` (plus **[Shared Analysis Flags](#4-shared-analysis-flags-reference)**)
```bash
skil compose .agents/skills --format json
skil compose taint .agents/skills --format terminal
skil compose assure .agents/skills --runtime-command ./bin/assurance-adapter --format json
```

---

### Category F: MCP Security, Local Discovery, Runtime Proxy, Telemetry & DevOps

#### `skil discover`
Discovers installed AI skills, MCP server configurations, and optional local AI execution runtimes across user home profiles and project workspaces (Claude Code, Claude Desktop, Cursor, VS Code, GitHub Copilot, Codex, OpenCode, Kiro, Gemini, Windsurf, Continue).
- `--home <dir>` (default: current user's `$HOME`): Home profile root to probe.
- `--workspace <dir>` (default: `""`): Project workspace directory to probe for repo-scoped agent configs.
- `--infra` (default: `false`): Probe local AI execution runtimes and server ports (Ollama, vLLM, LM Studio, TGI).
- `--format <terminal|json>` (default: `terminal`): Output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil discover --workspace . --infra --format json --output discovery.json
```

#### `skil mcp registry scan <file-or-server-name>`
Evaluates MCP Registry metadata (`server.json` or an official MCP Registry v0.1 server identifier) for supply-chain, publisher, transport, and repository-ownership drift risks.
- `--official` (default: `false`): Fetch the server record from the official MCP Registry v0.1 API.
- `--airgap` (default: `false`): Hard-fail if `--official` is enabled.
- `--expected-record-sha256 <sha256>` (default: `""`): Verify canonical SHA-256 of the registry record.
- `--reviewed-closure <contract.yaml>` (default: `""`): Verify against a reviewed closure contract.
- `--baseline <snapshot.json>` (default: `""`): Compare against a previous snapshot to detect repository ownership changes.
- `--format <terminal|json>` (default: `terminal`): Output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil mcp registry scan server.json --format json
skil mcp registry scan io.github.acme/server --official --format terminal
```

#### `skil mcp assure <skill>`
Launches an MCP server inside an isolated environment, performs a live protocol handshake, normalizes `camelCase`/`snake_case` tool schemas, verifies binary identity, and detects runtime tool poisoning or surface drift against declared contracts.
- `--runtime-command <executable>` (**required**): MCP server executable to launch and inspect.
- `--runtime-args <a,b>` (default: `""`): Comma-separated MCP server arguments.
- `--timeout <duration>` (default: `10s`): Handshake and discovery timeout.
- `--max-response-bytes <int64>` (default: `1048576`): Maximum frame size accepted from the server.
- `--format <terminal|json>` (default: `terminal`): Output format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil mcp assure ./my-mcp-skill --runtime-command ./bin/mcp-server --timeout 10s --format json
```

#### `skil mcp intercept`
Validates runtime MCP tool-call payloads against a pinned MCP surface lockfile (`.skil/mcp-surface.lock.json`) to block unauthorized dynamic tool registrations or schema rug pulls.
- `--lock <file>` (default: `".skil/mcp-surface.lock.json"`): Path to the MCP surface lockfile.
- `--strict` (default: `true`): Block any tool not present in the surface lock.
```bash
skil mcp intercept --lock .skil/mcp-surface.lock.json --strict
```

#### `skil serve`
Runs `skil` itself as a confined MCP scanner service over newline-delimited `stdio` or bearer-authenticated loopback HTTP.
- `--root <dir>` (**required**): Confined directory root; scan requests outside `--root` are rejected.
- `--stdio` (default: `false`): Serve MCP over `stdio`.
- `--listen <127.0.0.1:port>` (default: `""`): Serve authenticated HTTP on a loopback address.
- `--token-env <ENV>` (default: `"SKIL_MCP_TOKEN"`): Environment variable containing the HTTP Bearer token.
```bash
skil serve --stdio --root /workspace/skills
skil serve --listen 127.0.0.1:9090 --token-env SKIL_MCP_TOKEN --root /workspace/skills
```

#### `skil proxy serve`
Initializes the host-mediated runtime proxy for domain allowlisting, forbidden command blocking, and PII redaction.
- `--policy <file>` (default: built-in default policy): Custom proxy policy YAML/JSON.
- `--port <int>` (default: `8080`): Proxy listen port.
- `--format <terminal|json|yaml>` (default: `terminal`): Output format.
```bash
skil proxy serve --policy .skil/proxy-policy.yaml --port 8080 --format json
```

#### `skil mesh verify`
Verifies multi-agent service mesh identity, delegation boundaries, and mTLS/A2A trust configuration in a workspace.
- `--workspace <dir>` (default: `"."`): Workspace root directory.
- `--format <terminal|json>` (default: `terminal`): Output format.
```bash
skil mesh verify --workspace . --format json
```

#### `skil telemetry export <skill>`
Exports OpenTelemetry (`OTLP` JSON) trust and security evaluation trace spans for observability pipelines.
- `--format <otlp|json>` (default: `json`): Telemetry export format.
- `--output <file>` (default: stdout): Output file path.
```bash
skil telemetry export ./my-skill --format otlp --output telemetry-spans.json
```

#### `skil watch`, `skil fix`, `skil hook`, `skil ci` & `skil version`
- `skil watch [--workspace .] [--interval 2s]`: Watches a workspace for skill/contract modifications and re-runs continuous validation.
- `skil fix [--workspace .] [--dry-run]`: Automatically remediates common contract formatting, pinning, and frontmatter issues (`--dry-run` previews changes without writing).
- `skil hook install [--workspace .] [--strict]` / `skil hook uninstall [--workspace .]`: Installs or removes `skil` Git pre-commit / pre-push hooks.
- `skil ci init [--workspace .] [--platform github|gitlab] [--policy .skil/policy.yaml]`: Generates a ready-to-use GitHub Actions or GitLab CI security gate workflow.
- `skil version [--format plain|json]`: Prints version, VCS revision, dirty state, and semantic prompt version.
```bash
skil fix --workspace ./my-skill --dry-run
skil watch --workspace ./my-skill --interval 2s
skil version --format json
```

---

## 6. Secure Defaults & Exit Codes

Scanned content is always treated as **untrusted data, never executable instructions**:
- `skil scan` reads regular files and never imports Python modules, executes shell scripts, installs dependencies, starts MCP servers, or runs build hooks.
- Archive loading enforces strict bounds on file size, total extracted bytes, file count, compression ratios, and directory depth, rejecting path traversal (`..`), absolute paths, symlinks, and case collisions.
- Subprocess environments for external tools or isolated adapters are sanitized through an explicit allowlist (`internal/isolation`), stripping credential-shaped variables (`*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, cloud and SSH secrets).
- Checked-in `.skilignore` files support simple path or `directory/**` patterns and remain visible in the artifact manifest. `.gitignore` is deliberately ignored so security-relevant files cannot be hidden via Git ignore rules.

### Exit Codes

| Exit Code | Constant | Meaning |
| --- | --- | --- |
| `0` | `ExitOK` | Command / security gate passed (`PASS`). |
| `1` | `ExitGateFail` | Security scan, lint gate, verification, evaluation, or policy check failed (`FAIL` / `DENY` / `BLOCK`). |
| `2` | `ExitInput` | Invalid CLI arguments, malformed input artifact, schema violation, or disallowed airgap/remote flag combination. |
| `3` | `ExitInternal` | Unexpected internal or runtime failure. |

---

## 7. Documentation Index

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | System design, pipeline, and extension interfaces |
| [Toolchain](docs/toolchain.md) | Where `skil` fits among `skgate`, `skrun`, and `skcr`/`skpm`, and the responsibility boundary between them |
| [Skill contract](docs/skill-contract.md) | Versioned skill format and validation |
| [Linting](docs/linting.md) | Authoring checks and profiles |
| [Native security capabilities](docs/native-capabilities.md) | Built-in analyzers and rules |
| [Security model](docs/security-model.md) | Threat assumptions and trust boundaries |
| [Threat model](docs/threat-model.md) | Assets, attack surface, and countermeasures |
| [Known limitations](docs/security-scanning.md) | Static-scanning scope and blind spots |
| [CI and pre-commit integration](docs/ci-integration.md) | Official GitHub Action and pre-commit hooks |
| [Local component discovery](docs/local-discovery.md) | `skil discover`: known-location inventory of installed skills and MCP servers |
| [Transitive reference scanning](docs/transitive-scanning.md) | `skil scan --transitive`: bounded, opt-in traversal of external references a skill points at |
| [Assurance closure](docs/assurance-closure.md) | Fail-closed graph, typed states, deterministic digest, and lifecycle |
| [Continuous Agentic Assurance](docs/continuous-agentic-assurance.md) | Authorization continuity, subagent deltas, hierarchical budgets, and runtime verification |
| [Derived security views](docs/derived-security-views.md) | Bounded reconstruction, provenance, analyzer reuse, and incomplete-state behavior |
| [Air-gapped operation](docs/airgap.md) | `--airgap`: hard-fail before any work starts on any misconfigured network-capable flag |
| [Runtime assurance](docs/runtime-assurance.md) | Reviewed root/closure pins and per-operation enforcement |
| [Verification](docs/verification.md) | Declared-vs-observed capability checks |
| [Explainability](docs/explainability.md) | Operator-oriented explanations of scan results |
| [Policy](docs/policy.md) | Explainable install-time decisions |
| [Attestations](docs/attestations.md) | Digest-bound evidence and signatures |
| [Supply chain](docs/supply-chain.md) | SBOM, provenance, and dependency checks |
| [Semantic analysis](docs/semantic-analysis.md) | Provider-backed model passes |
| [MCP Registry posture](docs/mcp-registry.md) | Publisher and official-registry supply-chain checks |
| [Registry admission](docs/registry-admission.md) | Skill registry duplicate intelligence, capability overlap, and admission control |
| [External control crosswalk](docs/external-control-crosswalk.md) | Rule-ID mapping to external scanners |
| [External scanner feature parity](docs/external-scanner-feature-parity.md) | Differential harness results and rationale |
| [Competitive gap closure (2026-10)](docs/research/competitive-gap-closure-2026-10.md) | October 2026 competitive verification & capability gap matrix |
| [Release identity checklist](docs/release-identity-checklist.md) | Release hardening checklist |
| [Glossary](docs/glossary.md) | Terminology |

Additional deep-dive documents: [adversarial testing](docs/adversarial-testing.md), [behavioral testing](docs/behavioral-testing.md), [provider model](docs/provider-model.md), [capabilities](docs/capabilities.md), [extending analyzers](docs/extending-analyzers.md), [security control matrix](docs/security-control-matrix.md), and [COMPARISON.md](COMPARISON.md).

## Contributing & License

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community guidelines. Report security vulnerabilities privately per [SECURITY.md](SECURITY.md). Third-party attributions are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Licensed under [Apache-2.0](LICENSE).
