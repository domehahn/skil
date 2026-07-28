# ADR 0009: Independent security design

Status: accepted

Date: 2026-07-28

Owner: skil maintainers

## Context

`skil` needs broad skill-security analysis without presenting itself as a
clone, compatibility layer, or substitute for a named third-party scanner.
Security techniques such as syntax-tree inspection, dependency vulnerability
queries, data-flow analysis, signature matching, and policy enforcement are
implemented from public standards and the project's own requirements.

This record is an engineering risk-control decision, not legal advice.

## Decision

- Public rule IDs, categories, verdicts, scores, documentation, and CLI output
  use only `skil` terminology.
- The product does not publish a third-party rule-count or compatibility claim.
- Native controls are derived from threats and trust boundaries documented in
  this repository and are traceable to an engine and automated test.
- Third-party names may appear only in factual dependency/license notices or
  user-supplied evidence, never as product branding.
- Risk is expressed through the native `CLEAR`, `REVIEW`, and `BLOCK` verdicts
  and the existing `skil` weighted model.
- Optional integrations use open, vendor-neutral formats such as SARIF,
  in-toto, SLSA, OSV, JSON Schema, and YARA rule files.
- Executed evaluation is permitted only through a runtime that supplies an
  explicit isolation boundary. An unsandboxed process adapter fails closed.

## Alternatives

1. Mirror another scanner's rule names and counts. Rejected because it creates
   avoidable product-confusion and maintenance risk.
2. Copy an Apache-licensed implementation and retain notices. Rejected because
   no copied implementation is needed for the required behavior.
3. Remove overlapping security capabilities. Rejected because general
   security functions are necessary to the product; the implementation and
   expression remain independent.

## Security impact

The decision preserves defense-in-depth while removing catalog-only controls
that could imply protection not backed by executable evidence. Runtime
execution becomes fail-closed unless an isolation provider is configured.

## Legal-risk note

German copyright law distinguishes protected program expression from underlying
ideas and principles
([§ 69a UrhG](https://www.gesetze-im-internet.de/urhg/__69a.html)).
Trademark confusion is addressed separately by
[§ 14 MarkenG](https://www.gesetze-im-internet.de/markeng/__14.html).
Both trademark and unfair-competition questions remain fact-specific. A
qualified lawyer must review the final name, marketing, distribution package,
and third-party notices before commercial release.

## Review triggers

- A third-party rule catalog or source code is imported.
- Product naming, logos, screenshots, or comparative marketing changes.
- A new scanner-compatibility mode is proposed.
- Before the first commercial release.
