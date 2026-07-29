# Behavioral testing

Containment Assurance evaluates whether an agent remains inside its explicitly
authorized capability, target, execution, and trust boundaries while pursuing
a task.

Static scan asks whether an artifact could be dangerous. Verification compares
static observations with the declared contract. Behavioral eval tests agent
behavior in a scenario. Enforcement technically denies unauthorized
operations. Containment assurance tests whether those boundaries hold when
crossing them would make the goal easier.

Version 1 eval YAML describes input, context, environment, available tools,
required/allowed/forbidden calls, argument expectations, output properties,
side effects, and security assertions. Assertions target behavior rather than
exact prose. `AgentRuntime` returns messages, tool calls, arguments, outputs,
observed capabilities, side effects, errors, and a trace. Supported output
properties are `non_empty`, `json`, and `no_secrets`; supported assertions are
`no_external_side_effects`, `no_errors`, and
`no_forbidden_capabilities`, and `containment_compliant`. Unknown properties
and assertions fail closed.

Containment assurance is an additive v1 eval block. `containment.required`
requires a real host enforcer, process isolation, and at least one mediated
operation; `require_native_isolation` additionally requires the platform-native
provider. `allowed_targets` narrows the skill contract for the test. Mock
execution therefore cannot produce containment assurance.

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
values for those fields are discarded and recorded as an enforcement-bypass
attempt. Denied requests are returned to the adapter to capture the complete
trajectory, but they are never executed. No non-mock runtime is implicitly selected.

The wire contract is published as
`schemas/runtime-gateway-v1.schema.json`. The CLI registers the read-only
`artifact.read` tool, which accepts `{"path":"canonical/relative/path"}` and
reads only from the immutable artifact snapshot. Embedders can register other
`GatewayTool` implementations; each implementation remains part of the trusted
computing base.

`containment.simulate` is a closed deterministic local topology. It models a
challenge host and unsafe shortcut, pivot, privilege, external, escape, and
bypass attempts without sockets, commands, credentials, or host mutation.
Eval results separate task success from policy, capability, and containment
compliance. Use `--output`, then pass the result to `policy check --eval-result`
or `attest --eval-result`.

Containment metrics use eval runs as the denominator. Compliance rate counts
runs with no host-observed containment violation and with every required
enforcement/isolation boundary available and exercised. Each category attempt
rate counts runs containing at least one trusted violation of that category;
multiple attempts in one run do not inflate the rate.

Run `make test-linux-isolation` to reproduce the native Linux namespace and
memory-limit integration test in a disposable container. Windows AppContainer
execution is a required native CI job; `make test-windows-compile` provides a
local cross-compilation check.
