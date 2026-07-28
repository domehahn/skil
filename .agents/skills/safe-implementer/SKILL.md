---
name: "safe-implementer"
description: "Create or modify code, tests, configuration, and project files safely with real file changes."
version: "1.0.0"
since: "2026-07-28"
last_modified: "2026-07-28"
authors:
  - "platform-engineering"
stability: "stable"
min_platform_version:
  codex: "unknown"
  amazon-q: "unknown"
  antigravity: "unknown"
  auggie: "unknown"
  bob: "unknown"
  claude-code: "unknown"
  cline: "unknown"
  codebuddy: "unknown"
  continue: "unknown"
  costrict: "unknown"
  crush: "unknown"
  github-copilot: "unknown"
  gitlab-duo: "unknown"
  factory: "unknown"
  forgecode: "unknown"
  opencode: "unknown"
  openhands: "unknown"
  cursor: "unknown"
  roo-code: "unknown"
  kiro: "unknown"
  junie: "unknown"
  gemini-cli: "unknown"
  iflow: "unknown"
  kilocode: "unknown"
  kimi: "unknown"
  lingma: "unknown"
  pi: "unknown"
  qoder: "unknown"
  qwen: "unknown"
  windsurf: "unknown"
  ollama: "unknown"
deprecated_since:
replaces:
supersedes: []
changelog:
  - version: "1.0.0"
    date: "2026-07-28"
    change: "Initial generated production-ready SDLC / DevSecOps skill"
---
# Safe Implementer

## Purpose

Implement changes safely, minimally, and auditable while preserving public APIs, tests, rollback, input validation, error handling, safe defaults, and validation evidence.

## When to use

- The user asks for code, configuration, tests, documentation, or generated file changes.
- A requirement is ready for implementation.
- A bug fix needs a minimal, testable change.
- A migration or feature flag needs safe rollout treatment.
- Validation evidence must accompany the change.

## Operating model

1. Inspect existing patterns, tests, ownership boundaries, and generated-file flows before editing.
2. Implement only requested behavior and avoid broad refactoring.
3. Add or update tests for changed behavior and relevant failure paths.
4. Validate inputs at trust boundaries and handle errors safely.
5. Report changed files, validation evidence, rollback notes, and residual risk.

## Spec-Driven Change Context

- Treat repository specs, ADRs, runbooks, change proposals, design notes, and task files as durable context that outlives a chat session.
- For non-trivial changes, prefer a checked-in change artifact or equivalent proposal/design/tasks record before implementation begins.
- Capture requirement deltas explicitly: added, modified, removed, deprecated, or unchanged behavior.
- Keep implementation tasks traceable to acceptance criteria, affected specs, validation commands, and owners.
- During verification, compare the implementation against the proposal, design decisions, task checklist, and spec deltas.
- After completion, sync or archive completed change artifacts so the repository's source of truth reflects the final behavior.
- If the repository has no spec workflow yet, report the missing artifact and provide a minimal proposal/spec/tasks outline instead of relying on chat-only intent.

## Skill-Specific Review Scope

- Minimal change principle and no broad refactoring.
- Input validation, error handling, safe defaults, and API compatibility.
- Tests, validation evidence, rollback, and feature flags when appropriate.
- Secrets avoidance, no global side effects, and concurrency safety.
- Generated-file synchronization and reviewable diffs.

## Skill-Specific Checklist

- [ ] Implement only the requested behavior.
- [ ] Avoid broad refactoring unless explicitly required.
- [ ] Preserve public APIs unless a breaking change is explicitly requested.
- [ ] Add or update tests for changed behavior.
- [ ] Validate inputs at trust boundaries.
- [ ] Handle errors explicitly and safely.
- [ ] Avoid hardcoded secrets or credentials.
- [ ] Avoid global side effects and hidden state changes.
- [ ] Include rollback or mitigation notes for risky changes.
- [ ] Summarize changed files and validation performed.
- [ ] Keep generated outputs synchronized with canonical sources.
- [ ] Separate formatting-only churn from functional changes.

## Decision Rules

- If required behavior implies unrelated refactoring, ask before expanding scope.
- If a breaking API change is needed, require explicit approval and versioning.
- If input crosses a trust boundary, validate before use.
- If a migration is required, make rollout and rollback explicit.
- If tests cannot run, report the reason and residual risk.
- If generated files exist, update canonical sources and sync consistently.

## Finding Categories

- Scope creep or unrelated change.
- Missing tests or validation evidence.
- Unsafe input validation or error handling.
- API compatibility or migration risk.
- Secret exposure or unsafe configuration.
- Global side effect or hidden state change.

## Severity Guidance

- Critical: change introduces data loss, secret exposure, or unsafe production behavior.
- High: missing validation, rollback, or tests for risky behavior.
- Medium: maintainability or compatibility risk needs follow-up.
- Low: small cleanup, docs, or validation gap with limited blast radius.

## DevSecOps Guardrails

- Do not read secrets, `.env` files, private keys, production credentials, masked CI/CD variables, database dumps, or sensitive logs unless explicitly required.
- Do not push, deploy, publish, merge, or create releases unless explicitly asked.
- Prefer merge requests, reviewable diffs, and auditable validation evidence.
- Prefer least privilege, minimal changes, and explicit rollback notes.
- Do not fabricate test results, repository state, commands, security findings, or validation outcomes.
- Report assumptions, uncertainty, residual risk, and validation gaps clearly.

## Output Requirements

- Changed files and purpose of each change.
- Acceptance criteria satisfied by the implementation.
- Tests and validation commands run with results.
- Rollback or mitigation notes for risky changes.
- Known gaps, skipped checks, and residual risks.
- Generated files or sync actions performed.

## Acceptance Criteria

- Requested behavior is implemented without unrelated scope.
- Relevant tests or validation pass or failures are explained.
- Inputs and errors are handled safely.
- Public API compatibility is preserved or approved.
- No secrets or unsafe globals are introduced.
- Rollback and generated-file consistency are addressed.

## Anti-Patterns

- Broad refactoring in a narrow fix.
- Changing public APIs without approval.
- Skipping tests because the change is small.
- Swallowing errors or leaking internal errors externally.
- Hardcoding environment-specific secrets or URLs.
- Editing generated copies without updating canonical source.

## Changelog

### 1.0.0 - 2026-07-28

- Initial generated production-ready SDLC / DevSecOps skill.
