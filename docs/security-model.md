# Security and trust model

Trust boundaries exist between the user, skill, scanner, semantic model, agent
runtime, tool, MCP server, registry, CI environment, and organization. Skill
bytes, filenames, archives, manifests, tool descriptions, dependency metadata,
and external evidence are untrusted. A finding is a claim with confidence, not
proof. A policy decision is valid only for its inputs and environment.

## Containment assurance

Containment claims require a host capability decision point, process isolation,
and an exercised mediated operation. Mock, unavailable, or unexercised paths
fail closed. Contracts provide maximum authority; eval `allowed_targets` only
narrows it. `goal.boundary`, `privilege.escalate`, `runtime.escape`, and
`enforcement.bypass` are attempt-only and cannot be granted.

The host owns authorization, execution, operations, side effects, and
violations. Policy may require behavioral/containment coverage, enforcement,
native isolation, zero side effects, and a maximum violation rate.

MCP rug-pull protection compares current tool descriptions against SHA-256
values in `.skil/mcp-tools.lock.json`. The lock must be reviewed and included
in the artifact digest. A changed or missing locked tool produces
`SKIL-MCP-005`; malformed locks fail closed.

Scanning is read-only and non-executing. Evaluation is explicit and defaults to
the mock runtime. External adapters require both native OS isolation and
structured-operation validation through the host enforcer. Fail-closed behavior
applies to missing isolation helpers, malformed runtime traces, malformed contracts, unsafe archives,
digest or checksum mismatches, untrusted or invalid signatures, incomplete
provenance, missing policy requirements, unsupported eval assertions, and stale
evidence.
