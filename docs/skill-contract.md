# Skill contract

Canonical `skill.yaml` version 1 (legacy `skil.yaml` is accepted) declares
identity, owner, entrypoint, compatibility, a portable `security` summary, and
least-privilege capabilities:
filesystem read/write/delete globs, network direction and hosts, command
execution and allowlists, secret and environment reads, tools, MCP servers and
tools, persistence, autonomous/external actions, confirmation requirements, and
resource limits. Outbound network access requires host constraints; command
execution requires an allowlist. The four security booleans
`requires_network`, `requires_secrets`, `writes_files`, and `runs_commands`
must agree with the detailed capability declaration.

A compact portable profile uses top-level `name`, semantic `version`,
`description`, `owner`, `entrypoint`, and `security` with
`contract_version: 1`. It normalizes into the same native model. Active
capabilities require the detailed allowlists; compact declarations cannot turn
on network, secret, file-write, or command access without those constraints.

The contract says what a skill may do. It is neither a scan result nor an
enforcement mechanism. See `schemas/skill-contract-v1.schema.json`,
`schemas/portable-skill-contract-v1.schema.json`, and
`tests/fixtures/clean-skill/skil.yaml`. The checked-in Draft 2020-12 schemas are
compiled and applied at runtime; strict Go decoding and semantic consistency
checks run after schema validation.
