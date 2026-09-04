# ADR 0021: Host-Mediated Runtime Egress and Guardrail Proxy

## Context
Deploying skills into production agent environments carries runtime risk: agents may attempt unauthorized network requests, pass raw PII/secrets in tool parameters, or invoke unvetted subcommands. NeMo Guardrails provides runtime filtering, but SKIL requires a vendor-neutral, host-mediated local proxy that integrates directly with scanned skill capability baselines.

## Decision
1. Implement `internal/runtimeproxy` providing `skil proxy serve`.
2. Inspect incoming agent tool calls against scanned skill capability bounds and policy rules.
3. Validate parameter types and schemas, preventing untyped `type: any` parameter exploitation.
4. Redact sensitive patterns (PII, credentials, API tokens) in real-time before forwarding requests.
5. Enforce strict egress domain whitelists and subprocess execution limits, logging any guardrail violations.

## Status
Accepted.

