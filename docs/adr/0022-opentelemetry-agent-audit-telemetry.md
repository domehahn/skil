# ADR 0022: OpenTelemetry Agent Audit Telemetry

## Context
Enterprise security teams require real-time observability over AI agent operations, skill invocations, and guardrail enforcement events. Inspired by NeMo Observability, SKIL needs a standardized telemetry exporter compatible with OpenTelemetry (OTel).

## Decision
1. Implement `internal/telemetry` providing `skil telemetry export`.
2. Format skill audit evidence, tool execution events, latency, token usage, and trust score changes into OpenTelemetry-compliant trace spans (`otlp` JSON or JSONL format).
3. Allow streaming or batch export of telemetry logs to external observability collectors (Datadog, Grafana, OpenSearch, SIEM).

## Status
Accepted.

