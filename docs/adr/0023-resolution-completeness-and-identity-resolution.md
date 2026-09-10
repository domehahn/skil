# ADR 0023: Resolution Completeness and Identity Resolution

## Context
In static security analysis of agent skills, source code or instructions may be parsed successfully, but the exact execution target (subcommand, shell builtin, dynamic variable) may remain partially or completely unresolved at scan time (e.g., `runner="$USER_SELECTED_BINARY"; command "$runner"`). Treating a parsed wrapper or builtin as a fully understood execution target leads to false completeness.

## Decision
1. Implement `internal/completeness` providing `ResolutionEvidence`.
2. Classify security identity resolution into four explicit states:
   - `EXACT`: Execution target identity is fully and deterministically resolved.
   - `BOUNDED_SET`: Target is restricted to a known, closed set of candidate identities.
   - `PARTIAL`: Wrapper/shell builtin is understood, but target executable remains dynamic.
   - `RUNTIME_UNKNOWN`: Target identity cannot be resolved at scan time.
3. Ensure that `Source understood ≠ Execution target understood ≠ Analysis complete`.

## Status
Accepted.
