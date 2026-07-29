# Change 0007: Complete 42-control security matrix

Status: implemented

## Objective

Provide deterministic positive and negative coverage for all 42 scanner
controls documented in the security-control comparison. A positive case must
produce the intended finding or verification mismatch; its paired legitimate
negative case must not produce that control.

## Requirements

- Close contextual false positives for quoted role attacks, scoped warnings,
  fixed-argv subprocesses, authentication-only secret use, and normalized
  filesystem paths.
- Parse structured trigger declarations rather than relying only on lines.
- Add dedicated container-trust and Unicode-confusable controls.
- Make abandoned-package reputation available through trusted offline evidence.
- Detect MCP parameter-description injection and compare reviewed MCP metadata
  against an immutable local lock for rug-pull detection.
- Preserve existing rule IDs and version-1 contracts.

## Security decisions

- Reputation evidence and MCP locks are local, explicit, bounded, strict JSON;
  scanning never fetches package registries or MCP servers implicitly.
- Safe-code exceptions are narrow syntactic cases, not general suppression.
- Container and MCP integrity checks fail closed on malformed evidence.

## Validation

- Table-driven positive/negative tests for all 42 controls.
- Existing tests, race detector, vet, staticcheck, schemas, and diff review.

Completed locally on 2026-07-29:

- documented positive/negative matrix tests for controls 1–42
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `staticcheck ./...`
- `go mod verify`
- all embedded JSON Schemas parsed and compiled

## Rollback

All new controls are additive. Context refinements can be reverted
independently if they cause regression, without removing existing findings.
