# Contributing

Thanks for looking at skil. This document is the actual on-ramp: how to get
the repo running locally, how to find something to work on, and — the most
common contribution — how to add a new detection rule end to end, from an
empty idea to a merged PR.

If anything here is wrong or a step doesn't work as described, that's a bug
in this document; please open an issue for it.

## 1. Set up the repository locally

Requirements: Go 1.24+, a C toolchain (for the Tree-sitter bindings used by
the AST analyzers), and Docker only if you want to run the container-build
checks locally.

```bash
git clone https://github.com/domehahn/skil.git
cd skil
go build -o bin/skil ./cmd/skil
./bin/skil version
```

Run the full test suite and the same lint gate CI runs:

```bash
make test   # go test -race ./...
make lint   # gofmt -l + go vet
```

Both should be clean on an unmodified checkout. If they aren't, that's
itself worth an issue — see [Reporting a problem](#5-reporting-a-problem).

## 2. Find something to work on

- Issues labeled [`good first issue`](https://github.com/domehahn/skil/labels/good%20first%20issue)
  are scoped to be doable without deep familiarity with the rest of the
  codebase.
- Issues labeled [`help wanted`](https://github.com/domehahn/skil/labels/help%20wanted)
  are larger but still well-defined.
- [`analyzer`](https://github.com/domehahn/skil/labels/analyzer) — a new
  detection rule or a gap in an existing one.
- [`benchmark`](https://github.com/domehahn/skil/labels/benchmark) —
  differential/mutation-testing corpus work.
- [`provider`](https://github.com/domehahn/skil/labels/provider) —
  vulnerability/reputation/semantic provider integrations.
- [`testing`](https://github.com/domehahn/skil/labels/testing) — fixtures,
  regression coverage, CI.

If nothing fits, open an issue describing what you'd like to add before
writing code — for anything larger than a small fix, agreeing on the
approach first avoids wasted work.

## 3. The most common contribution: adding a detection rule

This is the full path from nothing to a merged rule, using a real example
shape. Every step below points at an actual file so you can open it
side-by-side.

### Step 1 — Reproduce or define the case

Write down, concretely, the artifact content that should trigger the rule
and the artifact content that should *not* (the false-positive case you're
guarding against). Both matter equally — a rule with no negative test is not
reviewable.

### Step 2 — Pick (or create) the analyzer

Detection rules live in `internal/analyzer/`, one file per security domain
(`credential_flow.go`, `mcp.go`, `multi_agent.go`, `data_classification.go`,
...). Look for an existing analyzer that already owns your domain before
creating a new file — most new rules are additions to an existing analyzer's
rule list, not a new analyzer.

Read [`docs/extending-analyzers.md`](docs/extending-analyzers.md) for the
`skil.Analyzer` interface contract. `internal/analyzer/credential_flow.go` is
a good template: it shows the regex-based `RulePattern` shape most rules use,
plus a structured (YAML/JSON-parsing) rule for properties that need more than
a line-local regex.

A rule needs, at minimum:

- a stable ID in the form `SKIL-<DOMAIN>-<NAME>` (grep existing IDs in
  `internal/analyzer/rules.go` for the convention in your domain — reuse an
  existing prefix rather than inventing a new one unless the domain is
  genuinely new)
- a title, category, and severity
- a description of what was observed and a remediation
- the detection logic itself (regex, AST match, or structural parse)

### Step 3 — Add fixtures

Every rule needs both a positive fixture (triggers the rule) and a negative
fixture (looks similar but should not). Follow the existing test file for
the analyzer you're editing — e.g. `credential_flow_test.go` pairs each rule
with a `Test<X>IsDetected` and a `Test<X>IsSafe` function using
`artifactWith(path, content)` and `hasRule(findings, ruleID)`. Keep the
negative fixture as close as possible to the positive one (change only the
one thing that should make it safe) — a negative fixture that's trivially
different from the positive doesn't prove anything about false positives.

### Step 4 — Register the rule

If your analyzer already exists and its `Analyze` method already returns
findings from its rule list, there's nothing further to register. If you
added a brand-new analyzer, add it to `DefaultRegistry` in
`internal/analyzer/registry.go`.

### Step 5 — Map it to an ASPS property

skil's rules are cross-referenced against the [Agent Skill Security
Properties Specification](compat/asps/asps-registry.json) (120 properties,
15 domains — see `docs/taxonomy.md`). Add or update the matching entry in
`internal/taxonomy/taxonomy.go` (a `Control{ID, Title, Domain, SKILRule}`
entry) so `skil conform` and the taxonomy registry know your rule exists.
If your rule closes a property that was previously `NEW` or `PARTIAL` in
`compat/asps/asps-crosswalk.csv` and `asps-registry.json`, update its
`skil_status` and `skil_controls` there too — `compat/asps/asps_conformance_test.go`
checks the two files stay in sync, and will tell you exactly what's wrong if
they don't.

### Step 6 — Check mutation robustness (for text/instruction rules)

If your rule matches natural-language instruction text, consider adding it
to the sample in `internal/analyzer/mutation_robustness_test.go`, which runs
your fixture through `internal/mutation`'s deterministic variant generator
(case folding, whitespace widening, homoglyphs, zero-width injection,
leetspeak) and reports how many variants still trigger the rule. This isn't
mandatory for every rule, but it's the fastest way to find out whether your
regex has an unintended assumption (e.g. a literal single space instead of
`\s+`) before a reviewer does.

### Step 7 — Run everything and open the PR

```bash
make lint
make test
```

Then open a PR. Include in the description: what the rule detects, why the
negative fixture is a legitimate case that should stay clean, and which ASPS
property (if any) it closes or strengthens.

## 4. Other kinds of contributions

- **Providers** (vulnerability, reputation, semantic) live under
  `internal/provider/`. They must remain optional — skil's default,
  offline behavior cannot depend on any of them — and must clearly disclose
  what network access or data they require. See `docs/provider-model.md`.
- **Benchmark/fixture work** happens in `compat/external-scanner/` (the
  differential-property harness against a pinned external reference) and
  `internal/mutation` (robustness testing). See
  `compat/external-scanner/README.md` for what the differential harness
  proves and does not prove.
- **Documentation** fixes are always welcome without a matching code change
  — `docs/` mirrors the architecture described in `docs/architecture.md`.

## 5. Reporting a problem

Use the bug report issue template. Include the exact input (artifact
content or command) that produced the wrong result, what you expected, and
what skil actually did. For a false positive or false negative on a
specific rule, include the rule ID from the finding.

For security vulnerabilities in skil itself, do not open a public issue —
follow [SECURITY.md](SECURITY.md) instead.

## 6. Review expectations

- `make lint` and `make test` must pass; CI re-runs both plus the ASPS
  crosswalk consistency check, the differential-harness regression tests,
  and platform-specific isolation/assurance checks.
- New providers, new capabilities, and new enforcement checks need a test
  demonstrating both the allow and the deny path.
- A Developer Certificate of Origin sign-off (`git commit -s`) is
  appreciated but not required.
