# Changelog

## Unreleased

## 0.2.0 - 2026-08-21

- Added a shared optional-analyzer pipeline for scan, verification,
  attestation, policy evaluation, and installation.
- Added common manifest/lock dependency inventory and deterministic SPDX 2.3
  SBOM output, plus exact Go-binary SBOMs from embedded build information.
- Added digest-guarded transactional update and uninstall operations.
- Added Linux hard-memory isolation, required native-sandbox CI, dependency
  vulnerability CI, native release builds, checksums, and OIDC attestations.
- Added a host-mediated multi-step tool gateway, Windows AppContainer/Job
  isolation, live native-OSV evidence, and release-attestation verification.
- Added canonical package validation, deterministic archives, atomic local
  installation, and `agent-skills.lock`.
- Added built-in Ed25519 signing and cryptographic policy verification for
  attestations, SLSA-v1 provenance, and external scanner evidence.
- Added concrete allowlist comparison, least-privilege warnings, complete
  behavioral assertion enforcement, and a host runtime capability gateway.
- Changed attestation/evidence-bundle/package-statement signing to sign a
  canonical JSON form (recursively key-sorted, exact-precision numeric
  literals) instead of Go's struct-declaration-order marshal, so that
  external verifiers (e.g. `skpm`, `SkillForge`) can independently validate
  a skil-produced signature from the wire JSON alone, without depending on
  skil's Go types. This changes the signed byte sequence for these types;
  signatures produced by earlier builds will not verify against this
  version and vice versa.

## 0.1.0 - 2026-07-28

- Initial Go release with secure artifact loading, static analysis, contracts,
  verification, policies, SARIF, baselines, behavioral evals, and attestations.
- Added Tree-sitter Python AST analysis, live OSV lookup, trusted-source YARA
  scanning, and a hardened OpenAI-compatible semantic provider.
