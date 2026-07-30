# ADR 0013: Replace SkillSpector with skil in production pipeline

Status: accepted

SkillSpector (`da5cb130`) is removed from CI. `skil` (`d09f693f`) is the sole security scanner. All six previously identified parity gaps (P2 Markdown, TR1–TR3 structured YAML triggers, EA3 scope creep, P8 privileged-context taint, OH1 model-output taint, EA4/OH3 infinite limits, SC5 reputation seeds) are closed. The differential harness reports 26/26 property passes with 0 external-only gaps.

`skil` is not a 1:1 drop-in for SkillSpector's `claude_cli`/`codex_cli` semantic providers or Pi extension, but those are not required for security detection. `skil` provides a superset of detection capability plus assurance-layer features (verification, attestation, policy, enforcement, SBOM) that SkillSpector does not offer.

Two prerequisites remain before claiming "complete functional superset" publicly: (1) a dual-scanner differential run against a corpus large enough for statistical confidence, (2) a blind holdout corpus v6/v7 generated after `d09f693f` to measure generalization. Both are scheduled but not blocking the pipeline switch.
