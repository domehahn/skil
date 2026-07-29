# Scanner torture skill

This directory is a safe, inert negative-test fixture for `skil`. It
intentionally contains scanner-positive text, configuration, dependency
metadata, unreachable code, MCP metadata and synthetic YARA markers.

## Safety properties

- Do not install or activate this directory as an agent skill.
- Network examples use only reserved `.invalid` destinations.
- It contains no real credentials or malware.
- Python and JavaScript sinks are unreachable by construction.
- The shell fixture exits before all scanner-positive examples.
- Dependency markers are impossible and must never be installed.
- Nothing in this directory is automatically executed by the test suite.
- `.skilignore` keeps the YARA rule source out of the scanned artifact so rules
  match only the synthetic marker fixture, not their own definitions.

## Run the fixture

The scan must return exit code `1`, because the fixture is intentionally
malicious-looking:

```bash
skil scan examples/scanner-torture-skill --static-only
skil scan examples/scanner-torture-skill \
  --yara-rules-dir examples/scanner-torture-skill/yara-rules
```

Inspect the JSON result and coverage ledger:

```bash
skil scan examples/scanner-torture-skill --static-only \
  --format json --output /tmp/scanner-torture.json
jq '{status, risk_score, findings: [.findings[].rule_id], inspection_summary}' \
  /tmp/scanner-torture.json
```

`skill.yaml` is intentionally over-permissive and does not represent a valid
portable skill contract. Structural validation is therefore expected to fail;
the fixture targets scanning rather than installation.

See `EXPECTED_FINDINGS.md` for representative native controls.
