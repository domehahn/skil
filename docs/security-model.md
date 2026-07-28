# Security and trust model

Trust boundaries exist between the user, skill, scanner, semantic model, agent
runtime, tool, MCP server, registry, CI environment, and organization. Skill
bytes, filenames, archives, manifests, tool descriptions, dependency metadata,
and external evidence are untrusted. A finding is a claim with confidence, not
proof. A policy decision is valid only for its inputs and environment.

Scanning is read-only and non-executing. Evaluation is explicit and defaults to
the mock runtime. External adapters require both native OS isolation and
structured-operation validation through the host enforcer. Fail-closed behavior
applies to missing isolation helpers, malformed runtime traces, malformed contracts, unsafe archives,
digest or checksum mismatches, untrusted or invalid signatures, incomplete
provenance, missing policy requirements, unsupported eval assertions, and stale
evidence.
