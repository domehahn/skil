# Skill contract

Canonical `skill.yaml` version 1 (legacy `skil.yaml` is accepted) declares
identity, owner, entrypoint, compatibility, the interoperable SkillSpec
`security` summary, and least-privilege capabilities:
filesystem read/write/delete globs, network direction and hosts, command
execution and allowlists, secret and environment reads, tools, MCP servers and
tools, persistence, autonomous/external actions, confirmation requirements, and
resource limits. Outbound network access requires host constraints; command
execution requires an allowlist. The four security booleans
`requires_network`, `requires_secrets`, `writes_files`, and `runs_commands`
must agree with the detailed capability declaration.

The contract says what a skill may do. It is neither a scan result nor an
enforcement mechanism. See `schemas/skill-contract-v1.schema.json` and
`tests/fixtures/clean-skill/skil.yaml`. The checked-in Draft 2020-12 JSON Schema
is compiled and applied at runtime; strict Go decoding and semantic consistency
checks run after schema validation.
