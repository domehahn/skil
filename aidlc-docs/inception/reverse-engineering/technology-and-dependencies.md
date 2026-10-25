# Technology Stack and Dependencies

## Runtime and build

- Go 1.24 module; local environment used Go 1.27.2 with `-buildvcs=false` because repository cache/VCS stamping was restricted.
- C toolchain required for official Tree-sitter bindings.
- Optional Docker, bubblewrap, util-linux, YARA, jq, and Python 3.12 support specific tests or workflows.
- Multi-stage non-root Docker image is built from `Dockerfile`.

## Direct Go dependencies

- AWS SDK v2 and Bedrock runtime for cloud model integration.
- Tree-sitter core plus Bash, JavaScript, Python, Ruby, and TypeScript grammars for syntax-aware analysis.
- `santhosh-tekuri/jsonschema/v6` for schema validation.
- `pelletier/go-toml/v2` for manifest/config parsing.
- `gopkg.in/yaml.v3` for YAML contracts and policy.

## Operational dependency posture

The default scanner is intended to be local and provider-free. Network-capable features are explicit: OSV, semantic providers, remote Git/archive inputs, external reputation/evidence, and YARA sources. CI verifies modules, runs vet/gofmt/lint/race tests, builds binaries, checks schemas, produces SBOMs, and executes security/compatibility gates.

## Delivery and release

CI runs on push and pull request. Release builds target Linux amd64, macOS arm64, and Windows amd64, run source tests and native assurance, build binaries and SPDX SBOMs, create GitHub attestations, verify exact provenance/SBOM bundles, and publish immutable tag assets.

## Observed risks and follow-up questions

- The repository is large and security-sensitive; changes should preserve digest identity, fail-closed semantics, coverage accounting, and public API compatibility.
- Local sandbox execution cannot validate network-binding tests; an unrestricted CI-like environment is required for those checks.
- README references some documentation paths that were not visible in the initial file inventory; documentation link completeness should be checked separately.
- The current checkout is at `93d3daa`, described as `v1.0.0-rc1` production-readiness completion, while the repository also contains historical v0.6/v0.7 tags and ongoing release workflows.
