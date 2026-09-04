# ADR 0019: Behavioral Live Evaluation Harness

## Context
Static analysis alone cannot observe how an AI agent skill behaves during execution under synthetic prompts, unexpected user inputs, or edge cases. To provide production-grade assurance (Tier 3 evaluation), SKIL requires an offline-first, sandboxed behavioral live evaluation harness that measures `Pass@K` metrics, tool execution fidelity, and error recovery.

## Decision
1. Implement `internal/evalharness` providing `skil eval run`.
2. Support configurable evaluation test suites with synthetic prompts, target criteria, expected tool invocations, and assertion rules.
3. Simulate agent execution in an isolated runner with deterministic mock LLM responses and tool invocation assertions.
4. Calculate standard behavioral metrics (`Pass@1`, `Pass@5`, Tool Call Accuracy, Error Recovery Rate) and export normalized scores into `internal/trust`.

## Status
Accepted.

