# ADR 0011: Host-mediated runtime gateway

Status: accepted

Date: 2026-07-29

Owner: skil maintainers

## Context

An isolated adapter can truthfully or dishonestly describe operations in its
final trace. OS isolation blocks direct host writes and network access, but a
reported trace is not proof that a real host tool was authorized or executed.

## Decision

- Process adapters use the versioned `GatewayExchange`/`GatewayMessage`
  protocol.
- Each isolated invocation may request one tool call or return one final
  response.
- Tool availability, implementation, capability derivation, authorization,
  execution, result limits, call budgets, and audit records belong to the
  trusted host.
- Adapter-owned tool calls, operations, capabilities, and side-effect records
  are rejected.
- The host returns only the bounded result of an authorized tool call to the
  next isolated invocation.
- Linux uses namespaces plus `prlimit`, macOS uses a deny-by-default profile,
  and supported Windows systems use an AppContainer without network
  capabilities plus a non-breakaway Job Object.

## Security impact

An adapter cannot turn a fabricated trace into authorization. Direct access
remains denied by the platform sandbox, while real effects can occur only
through a registered host tool and the contract enforcer. A compromised host
tool remains inside the trusted computing base and must validate its own
arguments.

## Rollback

The former one-shot trace protocol must not be restored as an enforcement
source. A rollback may disable isolated adapters entirely while retaining the
mock runtime.

## Review triggers

- A streaming or stateful adapter transport is introduced.
- A tool can perform more than one independently authorizable operation.
- A platform sandbox gains network access.
- Gateway results may contain secrets or exceed existing output bounds.
