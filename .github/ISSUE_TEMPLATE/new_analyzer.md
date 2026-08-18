---
name: New detection rule
about: Propose or track adding a new security detection rule
title: "analyzer: "
labels: analyzer
assignees: ""
---

<!--
See CONTRIBUTING.md section 3 for the full workflow (analyzer -> fixtures ->
rule ID -> ASPS mapping -> mutation test -> PR). This template is just the
checklist version.
-->

## What this rule detects

<!-- The exact artifact shape that should trigger it. -->

## What it should NOT flag (false-positive case)

<!-- The negative fixture case. -->

## Target analyzer

<!--
Which file in internal/analyzer/ does this belong to? If none fits, say so
and why a new analyzer file is needed.
-->

## ASPS property (if known)

<!-- e.g. ASP-04.06 — check compat/asps/asps-registry.json. Leave blank if unsure. -->

## Checklist

- [ ] Positive fixture
- [ ] Negative fixture
- [ ] Stable rule ID following the existing `SKIL-<DOMAIN>-<NAME>` convention
- [ ] ASPS taxonomy entry added/updated (`internal/taxonomy/taxonomy.go`,
      `compat/asps/asps-registry.json` + `asps-crosswalk.csv` if this closes
      a `NEW`/`PARTIAL` property)
- [ ] `make lint` and `make test` pass
