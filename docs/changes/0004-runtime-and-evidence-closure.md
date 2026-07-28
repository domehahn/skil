# Change 0004: Runtime and evidence closure

Status: implemented; external workflow runs retain the resulting evidence

Owner: skil maintainers

## Requirements and validation

| ID | Requirement | Acceptance criterion | Evidence |
| --- | --- | --- | --- |
| R-11 | Trusted tool audit | Adapter cannot supply host-owned audit fields. | Negative gateway unit test |
| R-12 | Real tool mediation | Host authorizes, executes, returns, and records a registered tool. | Multi-step gateway integration test |
| R-13 | Windows isolation | AppContainer has no network capabilities and a Job Object prevents process escape and enforces memory. | Windows CI native integration test |
| R-14 | Linux isolation evidence | Bubblewrap and hard memory limits run without a skip. | Required Linux CI integration test |
| R-15 | Online OSV evidence | Native provider detects a pinned, publicly documented vulnerable fixture. | Retained `osv-proof.json` CI artifact |
| R-16 | Attestation evidence | Each release archive is verified after attestation. | `gh attestation verify` release step |
| R-17 | Sandbox escape regression | Host writes and loopback network access are denied on every supported native platform. | Linux, macOS, and Windows native CI jobs |
| R-18 | Release SBOM accuracy | Release SBOM contains only modules linked into the exact binary and is bound to its digest. | Binary build-info SBOM regression test |

## Rollback

Disable the isolated runtime rather than accepting legacy adapter traces.
Remove a platform from advertised support if its native integration gate
cannot run. Do not bypass OSV or attestation verification after a transient
external-service failure; retry the workflow and retain the failed run.
