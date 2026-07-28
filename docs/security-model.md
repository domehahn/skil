# Security and trust model

Trust boundaries exist between the user, skill, scanner, semantic model, agent
runtime, tool, MCP server, registry, CI environment, and organization. Skill
bytes, filenames, archives, manifests, tool descriptions, dependency metadata,
and external evidence are untrusted. A finding is a claim with confidence, not
proof. A policy decision is valid only for its inputs and environment.

Scanning is read-only and non-executing. Evaluation is explicit and defaults to
the mock runtime. The provided host enforcer is a mediation library, not an OS
sandbox. Fail-closed behavior applies to malformed contracts, unsafe archives,
digest or checksum mismatches, untrusted or invalid signatures, incomplete
provenance, missing policy requirements, unsupported eval assertions, and stale
evidence.
