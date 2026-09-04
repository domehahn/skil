# SKIL Runtime Governance, Behavioral Evaluation & Red-Teaming Guide

This guide covers SKIL's advanced runtime governance, live behavioral evaluation, adversarial red-teaming, host-mediated guardrail proxying, and OpenTelemetry audit tracing capabilities (**SKIL v0.6.0**).

---

## 1. Live Behavioral Evaluation Harness (`skil eval run`)

SKIL evaluates skill execution quality and fidelity using synthetic test suites in isolated runners.

```bash
skil eval run ./my-skill --format json
skil eval run ./my-skill --suite custom-suite.json --output eval-results.json
```

### Measured Metrics
- **Pass@1 / Pass@5**: Task completion rate across synthetic test scenarios.
- **Tool Call Fidelity**: Percentage of expected tool invocations executed correctly.
- **Error Recovery Speed**: Success rate when handling simulated tool failures or invalid inputs.
- **Failure Escalation Safety**: Graceful degradation when encountering out-of-scope requests.

---

## 2. Adversarial Red-Teaming Engine (`skil probe`)

SKIL dynamically probes skills for injection vulnerabilities, jailbreaks, and tool parameter abuse.

```bash
skil probe ./my-skill --format json
skil probe ./my-skill --payloads INDIRECT_INJECTION,OBFUSCATION_ENCODING --output probe-report.json
```

### Probing Vectors
- **Indirect Prompt Injection (`SKIL-RED-001`)**: Hidden malicious instructions inside simulated data payloads.
- **Encoding & Steganography Obfuscation (`SKIL-RED-002`)**: Base64, Unicode homoglyphs, and zero-width character evasion.
- **Jailbreak & System Override (`SKIL-RED-003`)**: System prompt override attempt patterns.
- **Tool Argument Type & Boundary Abuse (`SKIL-RED-004`)**: Untyped argument injection and schema constraint violations.
- **Context Flooding (`SKIL-RED-005`)**: Excessive preamble payload attacks.

Calculates a **Vulnerability Exploitability Score (VES)** between `0.0` (invulnerable) and `1.0` (highly vulnerable).

---

## 3. Host-Mediated Guardrail Runtime Proxy (`skil proxy`)

SKIL runs a local host-mediated proxy to intercept agent tool calls, enforce schemas, redact PII, and block unauthorized egress.

```bash
skil proxy serve --port 8080 --policy .skil/proxy-policy.yaml
```

### Key Guardrails
- **Parameter Schema Enforcement**: Blocks untyped `type: any` parameter exploitation.
- **Real-Time PII & Secret Redaction**: Replaces credentials, API keys, and sensitive fields with `[REDACTED]`.
- **Egress & Subprocess Containment**: Enforces network domain whitelists and subprocess execution limits.

---

## 4. OpenTelemetry Audit Telemetry (`skil telemetry export`)

SKIL formats audit evidence and guardrail events into OpenTelemetry-compliant trace spans.

```bash
skil telemetry export audit-log.json --format otlp --output trace.json
```

Exports structured OTLP traces for Grafana, Datadog, or SIEM integration.

