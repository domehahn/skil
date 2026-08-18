# Change 0010: Native MCP Registry posture scanning

## Problem

MCP Registry metadata is useful discovery input but does not by itself prove
that a publisher identity, source repository, mutable deployment reference, or
downloaded artifact still matches a reviewed execution closure. Operators need
a deterministic pre-execution gate over publisher documents and official
registry responses.

## Decision

Add a standalone `internal/mcpregistry` inspection engine and expose it through
`skil mcp registry scan`. The engine accepts publisher and Registry v0.1 JSON,
rejects ambiguous duplicate keys, computes normalized record digests, evaluates
identity/version/transport/digest posture, and emits a stable JSON report. The
CLI owns bounded local I/O and the fixed, paginated official API adapter.

No MCP package, remote server, build hook, or registry-provided command is
executed. A registry record is treated as untrusted evidence, not as approval.

## Acceptance criteria

- local publisher, single-response, and list-response shapes are supported;
- official list scans consume every cursor page and latest scans use the v0.1
  latest-version endpoint;
- mutable versions, insecure URLs, identity drift, invalid package digests,
  review-closure mismatches, duplicate records, and latest inconsistencies fail
  the gate;
- reports bind raw sources and canonical records to SHA-256 digests;
- input size, redirects, symlinks, pagination, and input-overwrite risks are
  bounded or rejected;
- package and CLI tests cover clean, hostile, identity-drift, digest, pagination,
  duplicate-key, latest-version, and filesystem cases.

## Rollback

Remove the `mcp` command dispatch, `internal/mcpregistry`, and the associated
documentation/tests. The feature has no persisted state and changes no existing
scan or verification report schema.
