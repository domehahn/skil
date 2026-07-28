# ADR 0006: Explicit isolated agent runtime

Status: accepted

Evaluation alone uses `AgentRuntime`; scanning never executes skill content.
The default mock runtime is deterministic and side-effect free. External
adapters require an `IsolationProvider`, run with network and host writes
denied, and return structured operations that are validated by the contract
enforcer. Missing isolation support, unstructured side-effect claims, and
unenforceable memory limits fail closed.
