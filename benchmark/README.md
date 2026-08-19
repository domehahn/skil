# Vendor-neutral skill-security benchmark

This is a **vendor-neutral, public, reproducible** benchmark — not an
"independent" one. skil's own maintainers wrote this corpus and this runner,
so calling it independent would overstate what it is. It becomes
independently reviewed only once external reviewers are involved in the
ground-truth review process (see [Review status](#review-status) below).

This directory is deliberately separate from `compat/external-scanner/`,
which answers a different question ("does skil detect the same security
*properties* a pinned external tool's rule catalog defines") using skil's
own ASPS taxonomy as the reference frame. This benchmark instead measures
raw detection quality — TP/FP/TN/FN/Precision/Recall/F1/FPR — against a
ground truth that is **not** derived from skil, from any competing tool, or
from either's rule/property taxonomy.

## Why this is named differently from the rest of this repository

The rest of this repository (`README.md`, `COMPARISON.md`,
`compat/external-scanner/`) deliberately never names a specific competing
product — see `tests/independent_identity_test.go`. That test explicitly
excludes this directory (`benchmark/`), because a benchmark that won't say
which tool got which score isn't a benchmark; it's marketing copy with the
names filed off. Naming the tool here, with an exact version, is what makes
a result checkable.

## Scope of v1

- **Tools**: skil vs. [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)
  (Apache-2.0) only. Both are run from their own local, OSS build — no
  hosted/commercial API of either project. Cisco Skill Scanner and Tencent
  AI-Infra-Guard are the planned Phase 2 / Phase 3 additions once this
  methodology has proven itself against one adapter; Snyk Agent Scan has a
  broader endpoint-discovery focus and a hosted-token-based standard usage
  model that makes a direct like-for-like local comparison harder, so it's
  intentionally out of the main benchmark for now.
- **Track A (deterministic/offline) only.** Every adapter runs with LLM/
  semantic analysis disabled (skil: no `--semantic` flag; the reference
  tool: `--no-llm`). Mixing an LLM-backed run of one tool against a
  static-only run of the other would compare two different things and call
  it a scanner benchmark. A Track B (semantic/LLM-backed) is a distinct,
  future addition — see the "not yet done" list in `COMPARISON.md`.
- **No secrets, no commercial APIs**, anywhere in this benchmark or its CI
  workflow.

## Ground truth

Each fixture's `ground_truth.malicious` boolean and `ground_truth.category`
are set by this repository's maintainers and referenced against neutral,
versioned frameworks — not against skil's own rule IDs or ASPS taxonomy, and
not against the reference tool's rule IDs either:

- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- MITRE ATLAS techniques
- public security advisories

A tool gets credit (a true positive) for flagging the *security property*
the fixture demonstrates, regardless of which internal rule ID it uses to
do so — see `fixture.yaml`'s `rationale` field for what's actually being
asked.

### Hard negatives

Roughly half the corpus (`ground_truth.malicious: false`) is deliberately
adversarial toward naive keyword matching: text that names the same
trigger words as the malicious case but negates or contextualizes them
(`bench-007`), a comment that mentions a dangerous function only to explain
why it isn't used (`bench-008`), a credential file read that never reaches
a network sink (`bench-009`), and so on. These are worth more to this
benchmark than obvious malware, because they're where false positives
actually happen.

## Development vs. evaluation

```text
corpus/
├── development/   public, tunable, regression-only — never a headline metric
└── evaluation/    the blind holdout — the only tier a headline metric can come from
```

This split exists for one reason: **the moment a fixture is used to diagnose
or fix a scanner bug, it stops measuring generalization and starts measuring
"did we regress on a known case."** Both are useful, but conflating them is
how a benchmark quietly turns into a training set its own maintainer is
unknowingly optimizing against.

The rule, mechanically enforced by `run_benchmark.py` (`validate_tier_matches_dir`)
and by policy for everything the tooling can't check automatically:

> **A fixture that has ever been used to diagnose, reproduce, or fix a
> scanner bug belongs in `development/` permanently. It must never move to
> `evaluation/`, regardless of how old the bug or how thoroughly it's since
> been fixed.**

The 12 fixtures this benchmark launched with already found two real skil
false positives (issues #33, #34) — which is exactly why all 12 are
classified `tier: development` and always will be, even after those issues
are fixed and the fixtures become permanent regression tests. `evaluation/`
starts empty. Filling it requires fixtures nobody has used to tune anything
against, which in practice means writing them somewhat independently of
active bug-fixing work, or asking someone who isn't fixing skil's bugs to
contribute them.

## Review status

Every fixture starts at `review.status: provisional`. A fixture only
becomes `gold` after **at least two independent human reviewers** agree
with its `ground_truth` and `rationale`. `run_benchmark.py` computes three
numbers per tool:

- **headline_metric** — `tier: evaluation` AND `review.status: gold` only.
  This is the only number meant to be quoted anywhere (README, `COMPARISON.md`,
  external claims). As of this benchmark's initial version, `evaluation/` is
  empty, so the headline metric correctly reads `"n/a"` for every tool.
  That's the runner working as designed, not a bug.
- **development_set_metric_regression_only_never_a_generalization_claim** —
  every `development/` fixture, regardless of review status. Use this to
  check for regressions after a fix; never cite it as evidence of detection
  quality.
- **evaluation_set_provisional_metric_informational_only** — `evaluation/`
  fixtures not yet at `gold`. Useful for iterating on new holdout fixtures
  before they're reviewed; also not a headline number.

If you review a fixture, open a PR changing its `review.status` to `gold`
and adding yourself to `review.reviewers` (a second reviewer approves by
doing the same in a follow-up PR, not by rubber-stamping the first PR).

## Running it locally

```bash
# Build skil
go build -o /tmp/skil ./cmd/skil

# Install the reference scanner (Apache-2.0, from its own repository)
uv tool install git+https://github.com/NVIDIA/skillspector.git

pip install pyyaml
python3 benchmark/runner/run_benchmark.py \
  --skil-binary /tmp/skil \
  --skillspector-binary skillspector \
  --output benchmark/results/latest.json
```

Omit `--skillspector-binary` to run skil-only (no external install needed).

## CI

`.github/workflows/benchmark.yml` runs this weekly (`workflow_dispatch` also
available for on-demand runs) on a GitHub-hosted runner with `permissions:
contents: read` and no secrets — see that file's header comment for why this
is deliberately never a required PR gate: skil's trusted build chain must
not depend on a third party's release cadence, dependencies, or CLI
interface staying stable.

## Extending the corpus

See `schema/fixture-v1.schema.json` for the fixture format and
`corpus/development/bench-001-instruction-override/` for a complete
example. A new fixture PR should include both the artifact, a `rationale` a
reviewer who has never seen skil's or the reference tool's source code
could still evaluate, and a `tier` matching which directory it lives in.
New fixtures not tied to a specific bug diagnosis should generally start
directly in `evaluation/` (still `provisional` until reviewed) rather than
`development/`, so the holdout set actually grows.
