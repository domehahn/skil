# Provider model

Five narrow interfaces avoid an omnipotent provider:

- `SemanticProvider` analyzes explicitly untrusted text without tools.
- `VulnerabilityProvider` resolves package vulnerabilities.
- `SigningProvider` signs and verifies an artifact digest.
- `AgentRuntime` explicitly executes an eval and returns a trace.
- `EvidenceImporter` normalizes external scanner evidence.

Provider identity and availability must be reported. Provider failure does not
silently become completed coverage.

Concrete opt-in implementations ship for batched/cached OSV,
OpenAI-compatible and NVIDIA-compatible semantic analysis, native Anthropic
messages, Vertex-style Anthropic raw-predict proxies, and AWS Bedrock through
the official AWS SDK and SigV4 credential chain. The YARA analyzer uses the
installed upstream CLI because embedding libyara would impose a mandatory
CGO/system-library dependency on all users; skil provides a reviewed embedded
source pack, an explicit trusted source file, or a bounded flat trusted-source
directory to that CLI.
