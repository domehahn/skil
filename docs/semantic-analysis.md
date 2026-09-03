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
developer-intent, quality, and policy passes, then a constrained meta pass over their
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

Semantic output validation defaults to `--semantic-validation review`. Valid
findings remain available when a model also returns malformed findings; every
rejection is reported in `diagnostics` and `semantic-provider` coverage becomes
`degraded`. Use `--semantic-validation strict` for fail-closed workflows where
any invalid finding must fail the complete semantic pass.

A pass-level provider or response problem — a transport failure, an oversized
or malformed response, a non-2xx HTTP status, the provider truncating its own
output (OpenAI's `finish_reason=="length"`, Anthropic/Bedrock's
`stop_reason=="max_tokens"`), or more than 100 findings — never fails the
whole scan and never propagates as a Go error, in either mode: a provider
reports it as an *incomplete* pass instead (`SemanticDiagnostics.incomplete`),
which degrades `semantic-provider` coverage exactly like a per-finding
rejection does. A truncated response's surviving prefix is never parsed as a
complete one, even when it happens to look like valid JSON. This is
deliberate: treating a probabilistic provider's own hiccup as a hard error
would abort the entire scan and discard every deterministic analyzer's
already-computed findings along with it; degrading coverage instead keeps
the rest of the scan intact while still making sure `semantic-provider`
coverage — and, through the assurance closure, the overall result — never
implies `SAFE` on an incomplete semantic pass. Semantic Multi-Run Consensus
propagates an incomplete underlying run the same way: even though its zero
findings simply don't contribute to the majority vote, the run being
incomplete is never silently absorbed.

## Semantic Multi-Run Consensus

A single model call is inherently sampling-noise-prone: the same prompt
against the same content can produce a different finding set from one call to
the next, for reasons having nothing to do with the content itself.
`--semantic-runs N` (default `1`, a pure pass-through at no extra cost) repeats
every semantic pass `N` independent times and keeps a finding only when a
strict majority of the `N` runs found it at the same rule and location — a
finding one run reports but the rest don't is dropped entirely, not merely
down-weighted. A kept finding's confidence is rescaled by its agreement ratio
(`runs that found it / N`), and its evidence records the exact tally
(`consensus_runs`, `consensus_total`) so the decision is as inspectable as any
other finding's evidence.

The aggregation itself is fully deterministic given the `N` runs' outputs —
counting agreement across already-returned results, no additional model call
involved — so "was this finding kept" stays exactly as explainable and
reproducible as every other rule in skil, even though the underlying per-run
model calls are not reproducible themselves. `--semantic-runs` multiplies both
cost and wall-clock latency by `N` (`internal/provider/consensus` runs
sequentially, not in parallel, to stay simple and respect provider rate
limits): use it for a release gate or a periodic re-review, not routine
interactive scanning.
