# ADR 0010: Reproducible production assurance pipeline

Status: accepted

Date: 2026-07-28

Owner: skil maintainers

## Context

Optional vulnerability, malware, and semantic analyzers were initially wired
only to the interactive `scan` command. Verification, attestation, policy
checks, and installation therefore could not reproduce the same analysis
coverage. Runtime isolation also needs an explicit CI contract, and release
artifacts need machine-readable dependency evidence.

## Decision

- One analysis configuration builds the analyzer registry used by scan,
  verification, attestation, policy, and installation.
- Every evidence-producing or policy-enforcing command exposes the same
  opt-in analyzer flags and reports incomplete coverage fail-closed.
- Runtime isolation remains a separate trust boundary. CI must execute its
  native provider rather than silently accepting a skipped integration test.
- Runtime resource limits are advertised only when the isolation provider
  enforces them.
- Dependency inventory is exported as a native SPDX JSON SBOM and remains
  distinct from vulnerability verdicts.
- Installation lifecycle operations update installation state and lock state
  together or restore the previous state.

## Alternatives

1. Consume a previously generated scan file. Rejected as the only mechanism
   because it adds substitution and freshness risks; signed external evidence
   remains supported separately.
2. Keep command-specific analyzer flags. Rejected because coverage can drift
   between scan, attestation, and installation.
3. Claim memory enforcement through a timeout or trace field. Rejected because
   neither constrains process address space.

## Security impact

The same configured controls now protect preview, evidence creation, policy
evaluation, and installation. Optional providers remain explicit and may
transmit data only after user selection. Native runtime integration and
resource-limit tests become release gates on supported platforms.

## Rollback

Revert the shared pipeline as one unit. Do not fall back to silently reduced
analysis coverage or unenforced runtime limits.

## Review triggers

- A new analyzer provider or runtime platform is added.
- Scan evidence can be loaded instead of recomputed.
- The SBOM format or installation state model changes.
- A supported platform cannot execute the native isolation CI gate.
