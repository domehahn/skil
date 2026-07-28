# Provider model

Five narrow interfaces avoid an omnipotent provider:

- `SemanticProvider` analyzes explicitly untrusted text without tools.
- `VulnerabilityProvider` resolves package vulnerabilities.
- `SigningProvider` signs and verifies an artifact digest.
- `AgentRuntime` explicitly executes an eval and returns a trace.
- `EvidenceImporter` normalizes external scanner evidence.

Provider identity and availability must be reported. Provider failure does not
silently become completed coverage.

Concrete opt-in implementations ship for OSV and OpenAI-compatible semantic
analysis. The YARA analyzer uses the installed upstream CLI because embedding
libyara would impose a mandatory CGO/system-library dependency on all users.
