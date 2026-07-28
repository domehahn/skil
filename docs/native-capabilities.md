# Native security capabilities

`skil` is an independently designed skill-security verifier. Its public model
is organized around trust boundaries rather than a third-party rule catalog.

| Layer | Native implementation |
| --- | --- |
| Instruction integrity | contextual manipulation, unconditional-compliance, warning-removal, and guardrail-nullification controls |
| Code behavior | Tree-sitter AST analysis for Python, JavaScript, TypeScript, TSX, and Bash; reflective execution controls; bounded taint propagation |
| Data boundaries | environment/secret reads, filesystem access, outbound connections, generated-output trust |
| Dependencies | deterministic inventory for Go, JavaScript, Python, Rust, Ruby, and Maven; pinning, suspicious-name heuristics, reputation providers, and opt-in OSV queries |
| Tool protocols | structured JSON/YAML MCP permission and metadata validation with conservative text fallback |
| Malware analysis | trusted-source YARA adapter |
| Semantic intent | opt-in structured intent review through a hardened provider boundary |
| Contract verification | declared-vs-observed capabilities and concrete allowlists |
| Behavioral assurance | deterministic tests, a host-mediated tool gateway, and native isolation on Linux, macOS, and supported Windows AppContainer systems |
| Supply chain | content/package digests, SPDX 2.3 SBOMs, checksums, signatures, DSSE in-toto/SLSA provenance, and release attestations |
| Policy | digest-bound evidence, scanner identities, age/coverage thresholds, transactional install/update/uninstall gates |

Optional analysis is never reported as completed unless its provider actually
ran. Static analysis is intentionally bounded and can produce false positives
and false negatives. `skil capabilities` reports native runtime enforcement as
available only after the current platform provider passes its availability
probe.
