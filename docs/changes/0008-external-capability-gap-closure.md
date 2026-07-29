# Change 0008: external capability gap closure

## Scope

Compare skil with a dated public external scanner snapshot and close useful
capability gaps through independent Go implementation without copying foreign
rules, prompts, signatures, identifiers, scoring constants, branding, report
wording, or source code.

## Acceptance criteria

- Baselines support exact and reviewed drift-tolerant selectors with reason,
  approver, and expiry.
- Collection scans support bounded parallel workers and deterministic output.
- Trusted YARA rule directories are bounded, deterministic, and reject links
  and binary rules.
- Unicode tag smuggling and current cloud/container boundary risks are covered.
- Static instruction-integrity and exfiltration controls include conservative
  Chinese, Japanese, and Korean cases.
- Human-facing reports neutralize control/format characters.
- NVIDIA-compatible, Anthropic proxy, and native SigV4 Bedrock semantic
  transports preserve the no-tools contract.
- A non-root multi-stage container build is available.
- Unit, race, vet, static analysis, build, and scanner self-checks pass.

## Non-goals

- Reproducing third-party branding, rule IDs, exact regexes, YARA signatures,
  report wording, or score thresholds.
- Treating a frozen vulnerability sample as complete offline intelligence.
- Invoking local authenticated agent CLIs that cannot enforce the provider's
  no-tools/no-host-state boundary.
