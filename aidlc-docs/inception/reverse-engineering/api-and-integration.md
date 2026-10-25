# API and Integration Surface

## Public Go API

- `github.com/domehahn/skil/pkg/skil`: stable models, contracts, evaluation types, evidence/attestation types, assurance types, analyzer/provider interfaces, and operation/trust types.
- `github.com/domehahn/skil/pkg/engine`: `New`, `Register`, `Analyzers`, `Scan`, and `Rules` for embedding the deterministic scanner and adding analyzers.
- `github.com/domehahn/skil/pkg/enforcement`: `Enforcer`, `New`, `NewWithAssurance`, `Authorize`, `Decisions`, and `Ledger` for runtime capability decisions and budget evidence.

## CLI integration

The CLI is the primary integration surface. It supports terminal, JSON, YAML, Markdown, SARIF, and file output where applicable. CI integration is supplied by `.github/workflows/ci.yml`, release workflows, and the documented GitHub Action.

## External integrations

- AWS Bedrock runtime and AWS SDK configuration.
- OpenAI-compatible, NVIDIA-compatible, Anthropic, Anthropic proxy, and Bedrock semantic providers.
- OSV vulnerability service, with cache/offline controls.
- External YARA executable and built-in embedded YARA rules.
- Git and public HTTPS archive inputs when explicitly allowed.
- MCP registry and MCP interception/assurance surfaces.
- GitHub Actions artifact attestations, SBOM attestations, and release verification.
- Optional Docker/bubblewrap/util-linux native isolation paths.

## Serialized contracts

Versioned JSON schemas cover skill contracts, portable contracts, universal manifests, MCP locks/surface locks, package signatures, attestations, evidence bundles, provenance, policy, evaluation, runtime gateway, security evidence, dependency reputation, and skrun receipts.
