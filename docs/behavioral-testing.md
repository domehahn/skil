# Behavioral testing

Version 1 eval YAML describes input, context, environment, available tools,
required/allowed/forbidden calls, argument expectations, output properties,
side effects, and security assertions. Assertions target behavior rather than
exact prose. `AgentRuntime` returns messages, tool calls, arguments, outputs,
observed capabilities, side effects, errors, and a trace. Supported output
properties are `non_empty`, `json`, and `no_secrets`; supported assertions are
`no_external_side_effects`, `no_errors`, and
`no_forbidden_capabilities`. Unknown properties and assertions fail closed.

The deterministic mock runtime calls required available tools only. The
explicit `isolated` adapter exchanges versioned gateway JSON over stdin/stdout and is launched
only through a native OS isolation provider (`sandbox-exec` on macOS or
`bwrap` on Linux, or AppContainer on Windows). The built-in profile denies
network access and host writes, uses a minimal environment, and enforces
deadline and output bounds. Shell executables are rejected. Linux enforces
requested data/heap limits through `prlimit`; Windows uses a Job Object;
providers and platforms without a hard-memory primitive fail closed.

The adapter may request one tool call per isolated step. A registered,
host-side `GatewayTool` derives the operation from arguments, and
`pkg/enforcement.Enforcer` validates file, network, command, secret, tool, and
MCP operations against
allowlists, structured executable/argv prefixes, confirmations, tool-call
counts, network-byte budgets, and runtime deadlines. The trusted host executes
the tool, returns its bounded result on the next step, and constructs the tool,
operation, capability, error, and side-effect audit fields. Adapter-supplied
values for those fields are rejected. No non-mock runtime is implicitly
selected.

The wire contract is published as
`schemas/runtime-gateway-v1.schema.json`. The CLI registers the read-only
`artifact.read` tool, which accepts `{"path":"canonical/relative/path"}` and
reads only from the immutable artifact snapshot. Embedders can register other
`GatewayTool` implementations; each implementation remains part of the trusted
computing base.

Run `make test-linux-isolation` to reproduce the native Linux namespace and
memory-limit integration test in a disposable container. Windows AppContainer
execution is a required native CI job; `make test-windows-compile` provides a
local cross-compilation check.
