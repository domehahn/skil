# ADR 0024: Analysis Work Accounting Ledger

## Context
When scanning large or complex skill repositories, analyzers perform unit operations across files, AST nodes, quoted spans, and parameter definitions. If coverage findings fail to account for every scheduled unit of analysis work, false completeness metrics emerge.

## Decision
1. Implement `WorkLedger` in `internal/completeness` to record analysis work units.
2. Track explicit outcomes across 7 categories:
   - `scheduled`: Total units of work scheduled for analysis.
   - `processed`: Units fully analyzed without impediment.
   - `transformed`: Units analyzed via derived security view transformations.
   - `skipped`: Units explicitly bypassed by policy or baseline rules.
   - `unsupported`: Units matching unsupported constructs or languages.
   - `budget_exhausted`: Units skipped due to time or token limits.
   - `failed`: Units encountering analyzer errors.
3. Enforce the invariant: `scheduled = processed + transformed + skipped + unsupported + budget_exhausted + failed` (never `scheduled > known_outcomes`).

## Status
Accepted.

