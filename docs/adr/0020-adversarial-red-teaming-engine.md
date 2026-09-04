# ADR 0020: Adversarial Red-Teaming Engine

## Context
Static security scanning identifies known pattern vulnerabilities but cannot detect how a skill reacts to novel or mutated adversarial prompt injections, encoding tricks, or tool parameter abuse. Inspired by garak, SKIL requires a dynamic adversarial probing engine.

## Decision
1. Implement `internal/redteam` providing `skil probe`.
2. Generate mutated adversarial payloads across key risk vectors:
   - Indirect Prompt Injection
   - Encoding & Steganography Obfuscation (Base64, Unicode homoglyphs, Zero-width characters)
   - Jailbreak & System Prompt Override
   - Tool Argument Type & Boundary Abuse
   - Context Flooding / Overflow
3. Compute a Vulnerability Exploitability Score (VES, 0.0 to 1.0) and emit structured `skil.Finding` records mapped to rule IDs `SKIL-RED-001` .. `SKIL-RED-005`.

## Status
Accepted.

