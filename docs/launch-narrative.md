# Launch narrative

A draft positioning document and ready-to-adapt announcement post. Every
factual claim here links to something checkable in this repository —
`COMPARISON.md`, `benchmark/`, or a specific source file — consistent with
this project's own rule against unverifiable claims. Edit freely; the goal
is a starting point, not a fixed script.

## The one-sentence pitch

**A scan tells you what looked suspicious. skil builds evidence for
whether a specific skill may be trusted, installed, and allowed to act.**

## The problem, in three sentences

AI agent skills combine natural-language instructions, executable code,
tools, permissions, dependencies, and remote systems — and they're
installed with far less scrutiny than a normal software dependency.
Most tools that look at this problem answer one question: does this file
contain a suspicious pattern? That's necessary, but it stops at the exact
point an agentic system starts making its own decisions about what to run,
with what authority, and whether to run it again.

## What skil actually does differently

Most skill-security tools end at:

```text
skill → scan → findings → risk score
```

skil is a five-stage pipeline, and each stage produces its own durable,
checkable evidence rather than folding everything into one finding list:

```text
Detect → Verify → Decide → Attest → Enforce
```

- **Detect** — static analysis (Tree-sitter AST for Python/JS/TS/TSX/Bash,
  multi-hop taint tracking, dependency/OSV/typosquat checks, native
  malware signatures + YARA, Unicode/bidi/confusable/tag-smuggling
  detection, MCP protocol conformance, credential/identity-flow and
  multi-agent-delegation analyzers) plus optional semantic (LLM-backed)
  analysis, kept as a clearly separate track.
- **Verify** — declared-vs-observed capability verification: does the
  artifact actually do what it says it does, not just "did a pattern
  match somewhere."
- **Decide** — a policy engine that turns evidence into an explainable
  environment-specific decision, including first-class revocation
  (a compromised publisher key, artifact digest, or skill version can be
  revoked outright, overriding prior trust rather than merely withholding
  new trust).
- **Attest** — package signing, DSSE/in-toto provenance, and digest-bound
  attestation, so a decision can be checked later without re-running the
  scan.
- **Enforce** — a runtime capability gateway that can deny an operation
  live: a budget it's tracking (tokens, network bytes, tool calls,
  delegation/recursion depth, external mutations), a retry of a
  non-idempotent destructive action, untrusted data being promoted into
  an authorization-required context without explicit verification, or a
  runtime dependency whose digest doesn't match what was reviewed and
  pinned in advance (closing the classic TOCTOU gap between "we scanned
  version X" and "the process actually executed version Y").

See `COMPARISON.md` for the full capability matrix with links to the code
and tests behind every claim, and `docs/architecture.md` for the complete
picture.

## What we're *not* claiming (on purpose)

- Not "best detection." skil's rule set is broad and (per its own
  benchmark, see below) hasn't shown a known detection gap against the
  properties it's been checked against — but there is no gold-reviewed
  precision/recall/F1 number yet, and any claim like that would be
  unverifiable today. `benchmark/`'s headline metric correctly reads
  `"n/a"` until real independent review happens.
- Not "the most adopted." This is a young, single-maintainer-plus-agents
  project. It does not have an external contributor community yet — see
  the honest state in `COMPARISON.md` and the open call for help below.
- Not a fleet/endpoint-discovery platform, not a full red-teaming
  platform, not a hosted service. Deliberately scoped to one job: is this
  specific artifact, right now, allowed to do this specific thing.

## Proof points (all independently checkable)

- A vendor-neutral benchmark (`benchmark/`) runs skil against other OSS
  skill scanners from their own local builds — no hosted APIs, no secrets,
  a two-independent-reviewer gate before any number is allowed to be a
  headline metric, and a hard rule that a fixture used to fix a bug can
  never later count toward that tool's own generalization claim. Two
  genuine false positives in skil's own rules were found and fixed this
  way, with the fixtures kept as permanent regressions rather than quietly
  discarded.
- A deterministic mutation-testing harness (`internal/mutation`) measures
  how many lexical/encoding variants of a fixture (case, whitespace,
  homoglyphs, zero-width injection, leetspeak) still trigger the same
  rule — a robustness number, not just a pass/fail.
- A 120-property, 15-domain agentic security taxonomy (ASPS,
  `compat/asps/`) with per-domain conformance scoring (`skil conform`).

## What we're asking for

Not stars. Two concrete things:

1. **A second ground-truth reviewer for the benchmark** — 15–30 minutes
   evaluating a few fixtures under `benchmark/corpus/evaluation/` against
   their cited OWASP/MITRE reference. See
   [issue #36](https://github.com/domehahn/skil/issues/36).
2. **Real usage.** Scan a real skill you use, and open an issue for
   anything wrong — a miss, a false positive, a confusing error. See
   [CONTRIBUTING.md](../CONTRIBUTING.md); several `good first issue`s are
   already filed from bugs the benchmark itself found.

## Draft announcement post (Show HN / Reddit / blog style)

> **skil — an open-source assurance and enforcement framework for AI
> agent skills**
>
> Most tools that scan AI agent skills for security issues answer one
> question: does this file contain a suspicious pattern? skil does that
> too, but it's built around a different question: can this specific,
> digest-identified artifact be trusted to run, right now, with these
> exact capabilities — and can I prove that decision later without
> re-running anything?
>
> It's a five-stage pipeline (detect → verify → decide → attest →
> enforce), not just a rule engine: declared-vs-observed capability
> verification, a policy engine with first-class revocation, DSSE/in-toto
> attestation, and a runtime capability gateway that enforces resource
> budgets, trust-boundary promotion, idempotency on destructive retries,
> and TOCTOU-safe dependency-closure digest binding.
>
> It's young — single-digit stars, no external contributors yet — and
> deliberately honest about that: `COMPARISON.md` lists what's
> independently verifiable today and what isn't yet (no gold-reviewed
> benchmark numbers exist, on purpose — see `benchmark/`'s two-reviewer
> gate). If you scan agent skills for a living, or you'd spend 20 minutes
> reviewing a benchmark fixture, both are genuinely useful right now:
> [repo](https://github.com/domehahn/skil) ·
> [comparison](https://github.com/domehahn/skil/blob/main/COMPARISON.md) ·
> [benchmark reviewer call](https://github.com/domehahn/skil/issues/36)

## Where to post it

Venues where this kind of "young, technically deep, honestly-scoped OSS
security tool" post tends to land well: Hacker News (Show HN), r/netsec,
r/devsecops, the OWASP Agentic Skills Top 10 / Agentic Applications
community channels (skil's benchmark ground truth is built on their
taxonomy — a natural, genuine connection, not a cold pitch), and any
Slack/Discord where AI-agent-security practitioners already discuss
similar open-source scanners — since skil doesn't name specific competing
products in its own docs (see `COMPARISON.md`'s rationale), cross-posting
into spaces that already discuss that category of tool is the more
natural discovery path than trying to compete on search terms for a
specific product name.
