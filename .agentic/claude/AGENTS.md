# Claude Code Integration

The Claude Code adapter generates both skills and subagents.

## Generated structure

```text
CLAUDE.md
.claude/
├── skills/
│   └── <skill-name>/
│       └── SKILL.md
└── agents/
    └── <subagent-name>.md
Skills vs. Subagents

Skills are reusable instruction bundles.

.claude/skills/<skill-name>/SKILL.md

Subagents are specialized Claude Code workers with their own context, tool access, model, permissions, and system prompt.

.claude/agents/<subagent-name>.md
Generated subagents

The DevSecOps SDLC edition generates these Claude Code subagents when the claude platform is enabled:

requirements-analyst
architecture-reviewer
devsecops-reviewer
security-reviewer
ci-cd-reviewer
iac-gitops-reviewer
test-runner
release-readiness-reviewer
incident-postmortem-assistant
Invocation

Claude Code can delegate automatically when a task matches a subagent description.

You can also ask explicitly:

Use the security-reviewer subagent to review this change.

or:

Use the test-runner subagent to run relevant tests and summarize failures.
Design rules
Keep review subagents mostly read-only.
Use explicit tools.
Use skills: to preload relevant skill instructions into subagent context.
Prefer bounded, specialized subagents over generic workers.
Do not use subagents as a replacement for human review on security-sensitive changes.

---

## README-Ergänzung

Diesen Block in die Plattformübersicht deiner `README.md` einfügen:

```md
### Claude Code

Generated files:

```text
CLAUDE.md
.claude/skills/<skill-name>/SKILL.md
.claude/agents/<subagent-name>.md

Claude Code skills provide reusable instructions. Claude Code subagents provide specialized workers with their own context, tools, model, permissions, and preloaded skills.

The Claude adapter generates both:

skills under .claude/skills/<skill-name>/SKILL.md
subagents under .claude/agents/<subagent-name>.md

Subagents are useful for bounded review, testing, analysis, and DevSecOps tasks that would otherwise flood the main Claude Code conversation with logs, grep output, test output, or detailed review findings.


---

## `src/agentic_template_kit/templates/claude/CLAUDE.md.j2`

```md
# CLAUDE.md

## Claude Code Instructions

Project: skil  
Owner team: platform-engineering  
Governance level: standard

## Required behavior

- Make real file changes when implementation is requested.
- Do not only explain how to do the work.
- Do not commit, push, deploy, publish, or merge unless explicitly asked.
- Avoid secrets and sensitive files.
- Keep changes minimal, validated, and reviewable.
- Summarize changed files, validation results, and residual risks.

## Project Skills

Claude Code project skills are stored under:

```text
.claude/skills/<skill-name>/SKILL.md

Use slash commands where supported, or apply the matching skill instructions directly.



/requirements-analyst — Analyze requirements, user stories, acceptance criteria, constraints, risks, and open questions before implementation.


/cost-based-planner — Plan coding work with minimal context, relevant file selection, risk awareness, rollback, and validation strategy.


/architecture-reviewer — Review architecture, module boundaries, interfaces, coupling, scalability, data flows, and technical risks.


/threat-modeler — Identify assets, trust boundaries, abuse cases, attack paths, threats, and required security controls.


/safe-implementer — Create or modify code, tests, configuration, and project files safely with real file changes.


/test-strategy-engineer — Design and generate unit, integration, regression, security, and end-to-end test strategies.


/verification-reviewer — Review diffs, validate acceptance criteria, inspect test results, and find missed requirements.


/security-reviewer — Review code, CI/CD, configuration, permissions, dependencies, input validation, and DevSecOps risks.


/secrets-reviewer — Detect and prevent exposure of secrets, tokens, credentials, private keys, CI variables, and sensitive logs.


/dependency-supply-chain-reviewer — Review dependencies, lockfiles, package managers, container images, actions, and supply-chain risks.


/ci-cd-reviewer — Review CI/CD pipelines, runners, permissions, artifacts, caches, deployment gates, and token exposure.


/iac-gitops-reviewer — Review Terraform, Kubernetes, Helm, Kustomize, GitOps reconciliation, promotion, and environment safety.


/compliance-governance-reviewer — Review governance controls such as CODEOWNERS, branch protection, approvals, auditability, and policy compliance.


/release-readiness-reviewer — Assess release readiness, rollback, migrations, feature flags, monitoring, documentation, and breaking changes.


/observability-reviewer — Review logging, metrics, tracing, health checks, alerts, dashboards, runbooks, and operational readiness.


/incident-postmortem-assistant — Support incident analysis, timeline creation, root cause analysis, impact assessment, corrective actions, and follow-up issues.


/documentation-maintainer — Create and update README files, ADRs, setup guides, API docs, runbooks, and operational documentation.


/universal-skill-creator — Create, adapt, validate, and optimize reusable agent skills across agentic platforms.


/dora-readiness-reviewer — Review DORA readiness for ICT risk management, resilience testing, incidents, third-party risk, roles, policies, evidence, and auditability.


/ict-risk-management-reviewer — Review ICT risks, protection needs, criticality, controls, residual risks, treatment, and recurring reassessment.


/ict-third-party-risk-reviewer — Review cloud, SaaS, outsourcing, subcontractors, contracts, exit strategies, concentration risks, and DORA information-register readiness.


/ict-incident-reporting-reviewer — Review ICT incident classification, escalation, documentation, reportability, timelines, responsibilities, templates, and communication chains.


/operational-resilience-tester — Review backup and restore, failover, disaster recovery, restart procedures, crisis exercises, scenario tests, and lessons learned.


/audit-evidence-reviewer — Review evidence, approvals, tickets, logs, test protocols, risk decisions, versioning, and accountable owners.


/control-mapping-reviewer — Map technical measures to DORA, VAIT or BAIT migration needs, ISO 27001, BSI, internal policies, or MaRisk review expectations.


/outsourcing-exit-strategy-reviewer — Review exit plans, data return, provider transitions, emergency operations, suboutsourcing, cloud dependencies, and business impact.


/documentation-governance-reviewer — Review documentation freshness, ownership, review cycles, approvals, versioning, validity, and traceability.


/runbook-playbook-maintainer — Create and review runbooks, operating instructions, incident playbooks, escalation paths, restart procedures, and checklists.


/architecture-decision-recorder — Create and maintain ADRs with context, decisions, alternatives, risks, security impact, compliance relation, and review points.


/audit-traceability-maintainer — Link requirements, controls, implementation, tests, tickets, and evidence into an auditable trace.


/policy-documentation-maintainer — Create and update policies, standards, procedures, and control descriptions.


/evidence-package-creator — Create auditable evidence packages from tickets, pipeline results, test reports, approvals, scans, and architecture information.


/devsecops-maturity-reviewer — Assess maturity across plan, code, build, test, release, deploy, and operate with automation, security gates, ownership, and feedback loops.


/pipeline-security-architect — Design and review secure CI/CD pipelines with isolated runners, minimal rights, OIDC, signed artifacts, protected environments, and approval gates.


/software-supply-chain-architect — Review SLSA, provenance, SBOM, signatures, attestations, build integrity, artifact promotion, and trusted builders.


/policy-as-code-engineer — Create and review policies for OPA/Rego, Kyverno, GitLab Policies, Conftest, Checkov, Terraform, Kubernetes, and CI/CD gates.


/secure-developer-platform-reviewer — Review Internal Developer Platforms for secure golden paths, self-service guardrails, templates, permission models, secrets handling, and auditability.


/vulnerability-management-coordinator — Assess CVE triage, prioritization, SLAs, exploitability, asset criticality, exceptions, risk acceptance, and remediation tracking.


/cloud-landing-zone-reviewer — Review cloud accounts or subscriptions, networks, IAM, logging, policies, baselines, guardrails, encryption, tagging, and tenant separation.


/cloud-governance-reviewer — Review cloud naming, tags, ownership, cost centers, allowed services, regions, data classification, policy enforcement, and audit evidence.


/finops-reviewer — Review cloud costs, budgets, rightsizing, reserved or committed usage, anomalies, showback or chargeback, and team cost transparency.


/sre-reliability-reviewer — Assess SLOs, SLIs, error budgets, capacity, degradation, timeouts, retries, circuit breakers, load shedding, and operational risks.


/kubernetes-platform-reviewer — Review Kubernetes clusters, namespaces, RBAC, NetworkPolicies, Pod Security, admission controllers, resource limits, secrets, ingress, tenancy, and upgrades.


/gitops-operations-reviewer — Review Argo CD or Flux setups, sync policies, drift detection, promotion, rollback, app-of-apps, secrets, cluster access, and deployment governance.


/aiops-signal-correlation-reviewer — Assess correlation of logs, metrics, traces, events, and incidents to reduce noise, improve root-cause analysis, and lower alert fatigue.


/alert-quality-reviewer — Review alerts for actionability, clear symptoms, runbook links, severity, ownership, SLO relation, deduplication, escalation, and remediation suitability.


/auto-remediation-reviewer — Review automated repair actions for safe limits, dry runs, approval modes, rollback, audit logs, blast radius, and loop protection.


/mlops-governance-reviewer — Review model versioning, training data, bias, drift, monitoring, approvals, reproducibility, model registry, and deployment gates.


/llmops-security-reviewer — Review GenAI workloads for prompt injection, tool permissions, data exfiltration, RAG sources, sensitive prompt logging, evals, guardrails, and model access.


/ai-change-risk-reviewer — Review AI-assisted changes before execution for automation boundaries, human approval, affected-system criticality, and audit evidence.


/privacy-data-protection-reviewer — Review privacy, personal data, data classification, deletion concepts, purpose limitation, GDPR risks, and sensitive-data logging.


/api-contract-reviewer — Review REST, GraphQL, OpenAPI, and gRPC contracts, breaking changes, versioning, AuthN/AuthZ, error formats, and compatibility.


/secure-design-reviewer — Review secure-by-design decisions, least privilege, Zero Trust, tenant separation, secure defaults, and abuse scenarios.


/policy-as-code-reviewer — Review GitLab Security Policies, OPA/Rego, Kyverno, Conftest, Sentinel, admission policies, compliance pipelines, and central guardrails.


/container-security-reviewer — Review Dockerfiles, base images, user rights, capabilities, SBOM, image signing, distroless or slim images, CVEs, and runtime hardening.


/identity-access-reviewer — Review IAM, roles, service accounts, groups, tokens, OIDC federation, GitLab or GitHub permissions, cloud rights, and privilege-escalation paths.


/risk-acceptance-reviewer — Document and assess conscious risk decisions, impact and likelihood, expiry dates, and compensating measures.


/secure-code-reviewer — Review code vulnerabilities such as injection, path traversal, SSRF, XSS, deserialization, crypto misuse, and race conditions.


/performance-scalability-reviewer — Review load behavior, bottlenecks, caching, database access, queue behavior, scaling, timeouts, and resource limits.


/migration-change-reviewer — Review database migrations, schema changes, breaking changes, rollback ability, backward compatibility, and zero-downtime deployments.


/sbom-vulnerability-management-reviewer — Review SBOM generation, CVE triage, VEX, exception processes, patch SLAs, and the vulnerability lifecycle.


/developer-experience-reviewer — Review setup, local development, error messages, Makefiles or scripts, onboarding, tooling consistency, and practicality for teams.


/resilience-reviewer — Review timeouts, retries, circuit breakers, failover, backpressure, degraded modes, and resilience behavior.


/backup-restore-reviewer — Review restore tests, RPO/RTO, data integrity, backup protection, recoverability, and disaster recovery.



Project Subagents

Claude Code project subagents are stored under:

.claude/agents/<subagent-name>.md

Use subagents for bounded side tasks that would otherwise flood the main conversation with file reads, grep results, logs, test output, or security review detail.



requirements-analyst — Use proactively to analyze issues, user stories, acceptance criteria, constraints, risks, and missing requirements before implementation.


architecture-reviewer — Use proactively for architecture, module boundaries, interfaces, coupling, scalability, data flows, and technical design risks.


devsecops-reviewer — Use proactively after code, CI/CD, dependency, IaC, GitOps, or security-sensitive changes to review DevSecOps risk and merge readiness.


security-reviewer — Use proactively for authentication, authorization, input validation, file handling, permissions, secrets, and security-sensitive code changes.


ci-cd-reviewer — Use proactively for GitLab CI, GitHub Actions, runners, deployment jobs, caches, artifacts, tokens, and pipeline governance.


iac-gitops-reviewer — Use proactively for Terraform, Kubernetes, Helm, Kustomize, GitOps, environment promotion, reconciliation, and infrastructure changes.


test-runner — Use proactively to run relevant tests, analyze failures, and summarize validation results after implementation.


release-readiness-reviewer — Use proactively before release readiness claims to review tests, rollback, migrations, feature flags, monitoring, documentation, and breaking changes.


incident-postmortem-assistant — Use for incident analysis, log summaries, timeline reconstruction, root cause analysis, corrective actions, and follow-up issues.

Subagent routing

Use the matching subagent proactively when the task fits its description.

Recommended routing:

Requirements or acceptance criteria unclear → requirements-analyst
Architecture or module boundaries affected → architecture-reviewer
Security-sensitive behavior affected → security-reviewer
CI/CD or deployment logic changed → ci-cd-reviewer
Terraform, Kubernetes, Helm, Kustomize, or GitOps changed → iac-gitops-reviewer
Tests should be executed or failures analyzed → test-runner
DevSecOps merge-readiness review needed → devsecops-reviewer
Release readiness must be assessed → release-readiness-reviewer
Incident, outage, logs, or postmortem analysis needed → incident-postmortem-assistant
SDLC skill routing

For feature work, prefer:

/requirements-analyst
→ /cost-based-planner
→ /architecture-reviewer when architecture is affected
→ /threat-modeler when security-sensitive behavior is affected
→ /safe-implementer
→ /test-strategy-engineer
→ /verification-reviewer
→ /security-reviewer when needed
→ /documentation-maintainer when needed
→ /release-readiness-reviewer before release readiness claims

For CI/CD, dependency, IaC, GitOps, secrets, compliance, observability, or incident tasks, use the matching specialized skill or subagent before claiming completion.

Safety model
Prefer read-only subagents for analysis and review.
Use implementation through the main Claude Code session unless a subagent is explicitly designed to modify files.
Do not let review subagents perform broad rewrites.
Treat subagent output as review input; the main session remains responsible for final user-visible conclusions.

---

## `tests/test_templates.py` Ergänzung

In `EXPECTED_TEMPLATES` muss diese Datei enthalten sein:

```python
"claude/agent.md.j2",
