# Behavioral testing

Version 1 eval YAML describes input, context, environment, available tools,
required/allowed/forbidden calls, argument expectations, output properties,
side effects, and security assertions. Assertions target behavior rather than
exact prose. `AgentRuntime` returns messages, tool calls, arguments, outputs,
observed capabilities, side effects, errors, and a trace. Supported output
properties are `non_empty`, `json`, and `no_secrets`; supported assertions are
`no_external_side_effects`, `no_errors`, and
`no_forbidden_capabilities`. Unknown properties and assertions fail closed.

The deterministic mock runtime calls required available tools only. An explicit
`process` adapter exchanges JSON over stdin/stdout, invokes an executable
without a shell, uses a minimal environment, and enforces deadline and output
bounds. Shell executables are rejected. A requested hard memory limit fails
closed because the portable process adapter cannot enforce one; use an OS
sandbox adapter for that guarantee. No non-mock runtime is implicitly selected.

Hosts can place `pkg/enforcement.Enforcer` in front of a real runtime's file,
network, command, secret, tool, and MCP operations. The gateway enforces
allowlists, structured executable/argv prefixes, explicit confirmations,
tool-call counts, network-byte budgets, and runtime deadlines. It does not
replace an operating-system sandbox.
