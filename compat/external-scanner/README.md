# Differential security-property comparison

This directory is a live differential test harness, not a documentation
crosswalk: it actually executes skil and (optionally) an external reference
AI-skill security scanner against the same fixtures and reports whether each
tool detects the same underlying security property.

Consistent with this repository's independent-product-identity policy
(enforced by `tests/independent_identity_test.go`), the external tool is not
named here. See `docs/external-scanner-feature-parity.md` for the full
property-level crosswalk and rationale for why rule-ID parity is the wrong
model to compare against.

## Files

- `properties.yaml` — the gate corpus, keyed to the ASPS v1.0 taxonomy in
  `compat/asps/asps-registry.json` (120 properties). Each property carries its
  ASPS metadata (domain, invariant, detection, minimum evidence, OWASP/ATLAS
  crosswalk, `skil_status`) and a `fixtures` list: one entry per fixture
  directory, with the skil native rule ID(s) expected on the positive fixture
  and the external scanner's rule ID for the same property (for traceability
  back to the crosswalk doc only — this repository's production code never
  references it).
- `fixtures/<fixture>/positive/` and `.../negative/` — minimal artifacts
  exercising the property and a corresponding safe/negated case.
- `run_differential.py` — the runner.

## What this proves (and doesn't)

For each (property, fixture) entry, a fixture pair is scanned by both tools.
An entry "PASS"es on a side if that scanner's expected rule ID fires on the
positive fixture and does not fire on the negative fixture.

This does **not** assert:
- identical finding counts
- identical rule IDs
- identical severity

It asserts the property-level claim the mission cares about: **does skil
have zero unique gaps against fixtures the external scanner detects that
skil does not.** The summary line `Fixtures external-only: N [...]` is the
actual metric — it should be 0 for a property set believed to be at parity,
and any nonzero result is a real, actionable gap (not merely a
documentation todo).

## Running

skil-only (no external scanner required):

```bash
python3 run_differential.py --skil-binary /path/to/skil/bin/skil
```

Full differential (requires the external scanner's source available locally
and its runtime — this repository does not vendor or redistribute it):

```bash
python3 run_differential.py \
  --skil-binary /path/to/skil/bin/skil \
  --external-cmd "uv run --project /path/to/reference/clone <entry-point>"
```

Use `--filter <substring>` to run a subset of properties by id.

## Coverage

The corpus covers 120 ASPS properties with 173 fixture entries (74 properties
with fixtures spanning prompt injection, agent/MCP/peer-skill snooping,
privilege escalation, container escape, SSRF, behavioral manipulation,
physical-harm content, undisclosed operations, cloud exfiltration, filesystem
enumeration, MCP wildcard/parameter injection, Unicode homoglyphs, and Python
AST dynamic/reflective execution). The full property-level crosswalk lives in
`docs/external-scanner-feature-parity.md`. Extending coverage means adding a
`fixtures` entry plus a fixture pair; no runner changes are needed.

## Known result (informational, not a frozen benchmark)

As of the last local run: skil detected every fixture-positive case and the
external scanner missed several on the same fixtures — and, the metric that
matters, **0 fixtures where the external scanner detects something skil
misses**. Several of the external scanner's failures are its own false
positives on negated-safe fixtures (e.g. it lacks a negation guard on some
instruction-override phrasing, firing even on "Do not ignore previous
instructions"). This is a point-in-time result from the fixture set, not a
comprehensive or frozen benchmark — rerun it rather than trusting this number
as it ages.
