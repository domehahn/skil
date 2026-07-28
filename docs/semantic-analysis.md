# Semantic analysis

`SemanticProvider.AnalyzeUntrusted` is optional and vendor neutral. Requests
carry files as untrusted data, an artifact digest, an optional contract, and an
explicit no-tools constraint. Providers must disclose vendor, model, transmitted
data, and external processing before use. They receive no shell, MCP, tool, or
write interface from core. Semantic output is probabilistic and remains
separate from deterministic static findings.

The concrete OpenAI-compatible adapter is enabled with `--semantic` and requires
an explicit model. It sets `tool_choice: none`, requests a strict JSON schema,
validates every returned field, limits request/response sizes, disables
redirects, and blocks private, loopback, link-local, multicast, and metadata
addresses by default. Local endpoints require `--semantic-allow-private`.
Credentials are read only from the named environment variable.
