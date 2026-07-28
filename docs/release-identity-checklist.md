# Release identity and third-party review

This engineering checklist reduces avoidable product-confusion and license
risks. It is not legal advice and does not replace review by qualified counsel.

Before a public or commercial release:

- confirm the product name and logo through an appropriate trademark search;
- obtain legal review of naming, marketing claims, screenshots, and comparative
  statements;
- run `go test ./...` so the independent-identity regression checks public
  source and documentation;
- confirm public rule IDs use only the `SKIL-*` namespace;
- confirm no third-party rule counts, copied descriptions, screenshots, visual
  identity, or compatibility claims are present;
- generate a dependency/license inventory and retain required notices;
- distinguish standards and generic integrations (SARIF, OSV, YARA, in-toto,
  SLSA, JSON Schema) from third-party product branding;
- retain ADR 0009, test evidence, source history, and review approval as
  evidence of independent development;
- re-run the review whenever a third-party catalog, implementation, or product
  comparison is proposed.

Engineering rationale: [§ 69a UrhG](https://www.gesetze-im-internet.de/urhg/__69a.html)
distinguishes program expression from underlying ideas and principles, while
[§ 14 MarkenG](https://www.gesetze-im-internet.de/markeng/__14.html) addresses
confusingly similar signs in commerce. Application to a concrete release is a
legal determination.
