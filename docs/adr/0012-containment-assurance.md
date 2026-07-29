# ADR 0012: Containment assurance in the runtime gateway

Status: accepted

Containment extends the v1 eval, contract, enforcement, policy, and evidence
models. It does not add a parallel sandbox or policy engine. Contracts are the
maximum authority and eval target constraints only narrow them.

Denied requests return bounded gateway results so evaluation can capture the
full trajectory. The host records denial and never calls the tool.
Adapter-authored audit fields are discarded and become an enforcement-bypass
violation. Mock execution cannot claim containment; required native isolation
is a separate coverage dimension.

The built-in topology is pure simulation. This enables safe deterministic
regression testing, but is not a penetration test or proof against sandbox
implementation vulnerabilities.
