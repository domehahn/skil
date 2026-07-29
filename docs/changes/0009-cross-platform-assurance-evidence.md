# Change 0009: Cross-platform assurance evidence

Status: implemented

Owner: platform-engineering

## Requirement delta

- Add a positive, real-CLI `skil assure` gate on supported Linux, macOS, and
  Windows runners.
- Retain the digest-bound JSON result as CI evidence.
- Exercise the public HTTPS gateway and deterministically test DNS rebinding
  and cancellation.
- Add a controlled manual smoke path for credentialed semantic providers.
- Publish Windows release artifacts and verify downloaded attestations and
  checksum-backed subjects before release creation.

## Acceptance evidence

| Requirement | Automated evidence |
| --- | --- |
| Native assurance | `.github/workflows/ci.yml` `assurance-e2e` matrix |
| Deterministic adapter | `internal/evaltestadapter` unit and negative tests |
| Linux local reproduction | `make test-linux-assurance` |
| Network hardening | `internal/eval/gateway_tools_test.go` plus `network-gateway` CI job |
| Semantic provider | manually approved `semantic-provider-smoke` workflow |
| Release integrity | native Linux/macOS/Windows build matrix, SBOM attestations, transport re-verification, checksums |

The full Windows CGO build is pinned to `windows-2022`, whose hosted image
retains MinGW; the separate AppContainer integration test also runs on
`windows-latest`. macOS jobs use `macos-15` rather than the announced
deprecating macOS-14 image.

## Rollback

The new CI jobs and test adapter can be removed without changing the public
runtime protocol. Release rollback means disabling publication; immutable
release assets must never be overwritten.
