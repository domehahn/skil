# Semantic analysis

Every scan includes a deterministic local semantic pass. It extracts explicit
bounded-behavior claims from Markdown, such as read-only, no outbound network,
no process execution, or no secret access, and correlates them with
syntax-derived observations across the complete artifact. This offline pass
requires no model, credentials, or provider and is reported as `semantic`.

`SemanticProvider.AnalyzeUntrusted` is optional and vendor neutral. Requests
carry files as untrusted data, an artifact digest, an optional contract, and an
explicit no-tools constraint. Providers must disclose vendor, model, transmitted
data, and external processing before use. They receive no shell, MCP, tool, or
write interface from core. Semantic output is probabilistic and remains
separate from deterministic static findings.

Opt-in model-backed semantic analysis runs independent security,
developer-intent, and quality passes, then a constrained meta pass over their
findings, and deduplicates only identical native findings. Its separate
coverage key is `semantic-provider`. The OpenAI-compatible
adapter sets `tool_choice: none` and requests a strict JSON schema. The native
Anthropic adapter omits tools and validates the same bounded result contract.
Select it with `--semantic-provider anthropic`. NVIDIA's OpenAI-compatible
endpoint has a named `nvidia` preset. Vertex-style raw-predict gateways use
`anthropic-proxy`; AWS Bedrock uses `bedrock` with `--semantic-region` and the
standard AWS SDK credential chain.

Both adapters require an explicit model, validate every returned field, limit
request/response sizes, disable redirects, and block private, loopback,
link-local, multicast, and metadata addresses by default. Local endpoints
require `--semantic-allow-private`. HTTP-provider credentials are read only
from the named environment variable. Bedrock credentials are resolved and
requests are SigV4-signed by the official AWS SDK. No semantic provider
executes a local agent CLI: such CLIs can retain read capabilities and local
authentication state even in their strictest sandbox modes, which does not
satisfy skil's no-tools provider contract.
