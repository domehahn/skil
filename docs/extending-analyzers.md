# Extending analyzers

Implement `skil.Analyzer` with immutable metadata and
`Analyze(context.Context, skil.AnalysisContext)`. Register it with the analyzer
registry from public package `pkg/engine`; duplicate IDs are rejected. An analyzer must be deterministic where
possible, treat bytes as data, avoid execution and hidden networking, respect
context cancellation, use stable rule IDs, and return location, evidence,
remediation, confidence, and stable fingerprints. Each rule needs positive and
negative fixtures plus a severity rationale.
