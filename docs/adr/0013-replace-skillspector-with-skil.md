# ADR 0013: Replace SkillSpector with skil in production pipeline

Status: accepted

SkillSpector (`da5cb130`) is removed from CI. `skil` (`6b160a5`) is the sole security scanner. All parity gaps are closed against the 86-property corpus in `compat/external-scanner/properties.yaml`: the static differential gate reports 67/67 property passes with zero external-only gaps (FULL 78, DIFFERENT_BY_DESIGN 6, PROVIDER_BACKED 2; no PARTIAL, no MISSING), enforced by `TestNoUnresolvedPARTIALOrMISSING` and the crosswalk drift check.

`skil` is not a 1:1 drop-in for SkillSpector's `claude_cli`/`codex_cli` semantic providers or Pi extension, but those are not required for security detection. `skil` provides a superset of detection capability plus assurance-layer features (verification, attestation, policy, enforcement, SBOM) that SkillSpector does not offer.

The prerequisites for claiming "complete functional superset" publicly are fulfilled: (1) the dual-scanner differential harness runs against the full 86-property corpus (static suite 67/67 with 0 external-only gaps; provider-backed OSV/YARA scans in a separate `provider` suite), and (2) blind holdout corpora v6/v7 (post-`d09f693f`) and v8 (post-`6b160a5`, covering the new external-transfer, tool-agency grant-form, output-boundary, indirect-leak, memory-persistence, manifest-staging, code-level FS, cloud-SDK, internal-SSRF, shell-privilege, and false-memory-reset rules) measure generalization and are regression-frozen.
