# Explainability

`skil explain` consumes a previously generated JSON scan result and produces an operator-oriented explanation without rescanning the artifact:

```bash
skil scan ./my-skill --static-only --format json --output scan.json
skil explain scan.json
skil explain scan.json --format json --output explanation.json
```

The explanation is derived from the canonical `ScanResult`. It reports the artifact identity, status, verdict, active findings, incomplete analysis, exceeded budgets, closure limitations, opaque content, and suggested next actions. `authoritative` is false whenever the result is incomplete, budget-limited, opaque, or otherwise non-final.

The JSON projection is versioned by `schemas/explanation-v1.schema.json` and is intentionally additive to the existing scan-result contract.

The command does not turn `UNKNOWN` or incomplete evidence into a safe result. Exit-code behavior follows scan semantics: `0` for non-blocking results, `1` for a blocking result, and `2` for invalid input.
