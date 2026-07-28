# GitHub Copilot Repository Instructions

Project: skil  
Owner team: platform-engineering  
Governance level: standard

GitHub Copilot does not use `SKILL.md` project skills like Codex or GitLab Duo. This repository provides reusable prompt files under:

```text
.github/prompts/*.prompt.md
```

## Available prompt capabilities


- `requirements-analyst.prompt.md` — Analyze requirements, user stories, acceptance criteria, constraints, risks, and open questions before implementation.

- `cost-based-planner.prompt.md` — Plan coding work with minimal context, relevant file selection, risk awareness, rollback, and validation strategy.

- `architecture-reviewer.prompt.md` — Review architecture, module boundaries, interfaces, coupling, scalability, data flows, and technical risks.

- `threat-modeler.prompt.md` — Identify assets, trust boundaries, abuse cases, attack paths, threats, and required security controls.

- `safe-implementer.prompt.md` — Create or modify code, tests, configuration, and project files safely with real file changes.

- `test-strategy-engineer.prompt.md` — Design and generate unit, integration, regression, security, and end-to-end test strategies.

- `verification-reviewer.prompt.md` — Review diffs, validate acceptance criteria, inspect test results, and find missed requirements.

- `security-reviewer.prompt.md` — Review code, CI/CD, configuration, permissions, dependencies, input validation, and DevSecOps risks.

- `secrets-reviewer.prompt.md` — Detect and prevent exposure of secrets, tokens, credentials, private keys, CI variables, and sensitive logs.

- `dependency-supply-chain-reviewer.prompt.md` — Review dependencies, lockfiles, package managers, container images, actions, and supply-chain risks.

- `ci-cd-reviewer.prompt.md` — Review CI/CD pipelines, runners, permissions, artifacts, caches, deployment gates, and token exposure.

- `iac-gitops-reviewer.prompt.md` — Review Terraform, Kubernetes, Helm, Kustomize, GitOps reconciliation, promotion, and environment safety.

- `compliance-governance-reviewer.prompt.md` — Review governance controls such as CODEOWNERS, branch protection, approvals, auditability, and policy compliance.

- `release-readiness-reviewer.prompt.md` — Assess release readiness, rollback, migrations, feature flags, monitoring, documentation, and breaking changes.

- `observability-reviewer.prompt.md` — Review logging, metrics, tracing, health checks, alerts, dashboards, runbooks, and operational readiness.

- `incident-postmortem-assistant.prompt.md` — Support incident analysis, timeline creation, root cause analysis, impact assessment, corrective actions, and follow-up issues.

- `documentation-maintainer.prompt.md` — Create and update README files, ADRs, setup guides, API docs, runbooks, and operational documentation.

- `universal-skill-creator.prompt.md` — Create, adapt, validate, and optimize reusable agent skills across agentic platforms.

- `dora-readiness-reviewer.prompt.md` — Review DORA readiness for ICT risk management, resilience testing, incidents, third-party risk, roles, policies, evidence, and auditability.

- `ict-risk-management-reviewer.prompt.md` — Review ICT risks, protection needs, criticality, controls, residual risks, treatment, and recurring reassessment.

- `ict-third-party-risk-reviewer.prompt.md` — Review cloud, SaaS, outsourcing, subcontractors, contracts, exit strategies, concentration risks, and DORA information-register readiness.

- `ict-incident-reporting-reviewer.prompt.md` — Review ICT incident classification, escalation, documentation, reportability, timelines, responsibilities, templates, and communication chains.

- `operational-resilience-tester.prompt.md` — Review backup and restore, failover, disaster recovery, restart procedures, crisis exercises, scenario tests, and lessons learned.

- `audit-evidence-reviewer.prompt.md` — Review evidence, approvals, tickets, logs, test protocols, risk decisions, versioning, and accountable owners.

- `control-mapping-reviewer.prompt.md` — Map technical measures to DORA, VAIT or BAIT migration needs, ISO 27001, BSI, internal policies, or MaRisk review expectations.

- `outsourcing-exit-strategy-reviewer.prompt.md` — Review exit plans, data return, provider transitions, emergency operations, suboutsourcing, cloud dependencies, and business impact.

- `documentation-governance-reviewer.prompt.md` — Review documentation freshness, ownership, review cycles, approvals, versioning, validity, and traceability.

- `runbook-playbook-maintainer.prompt.md` — Create and review runbooks, operating instructions, incident playbooks, escalation paths, restart procedures, and checklists.

- `architecture-decision-recorder.prompt.md` — Create and maintain ADRs with context, decisions, alternatives, risks, security impact, compliance relation, and review points.

- `audit-traceability-maintainer.prompt.md` — Link requirements, controls, implementation, tests, tickets, and evidence into an auditable trace.

- `policy-documentation-maintainer.prompt.md` — Create and update policies, standards, procedures, and control descriptions.

- `evidence-package-creator.prompt.md` — Create auditable evidence packages from tickets, pipeline results, test reports, approvals, scans, and architecture information.

- `devsecops-maturity-reviewer.prompt.md` — Assess maturity across plan, code, build, test, release, deploy, and operate with automation, security gates, ownership, and feedback loops.

- `pipeline-security-architect.prompt.md` — Design and review secure CI/CD pipelines with isolated runners, minimal rights, OIDC, signed artifacts, protected environments, and approval gates.

- `software-supply-chain-architect.prompt.md` — Review SLSA, provenance, SBOM, signatures, attestations, build integrity, artifact promotion, and trusted builders.

- `policy-as-code-engineer.prompt.md` — Create and review policies for OPA/Rego, Kyverno, GitLab Policies, Conftest, Checkov, Terraform, Kubernetes, and CI/CD gates.

- `secure-developer-platform-reviewer.prompt.md` — Review Internal Developer Platforms for secure golden paths, self-service guardrails, templates, permission models, secrets handling, and auditability.

- `vulnerability-management-coordinator.prompt.md` — Assess CVE triage, prioritization, SLAs, exploitability, asset criticality, exceptions, risk acceptance, and remediation tracking.

- `cloud-landing-zone-reviewer.prompt.md` — Review cloud accounts or subscriptions, networks, IAM, logging, policies, baselines, guardrails, encryption, tagging, and tenant separation.

- `cloud-governance-reviewer.prompt.md` — Review cloud naming, tags, ownership, cost centers, allowed services, regions, data classification, policy enforcement, and audit evidence.

- `finops-reviewer.prompt.md` — Review cloud costs, budgets, rightsizing, reserved or committed usage, anomalies, showback or chargeback, and team cost transparency.

- `sre-reliability-reviewer.prompt.md` — Assess SLOs, SLIs, error budgets, capacity, degradation, timeouts, retries, circuit breakers, load shedding, and operational risks.

- `kubernetes-platform-reviewer.prompt.md` — Review Kubernetes clusters, namespaces, RBAC, NetworkPolicies, Pod Security, admission controllers, resource limits, secrets, ingress, tenancy, and upgrades.

- `gitops-operations-reviewer.prompt.md` — Review Argo CD or Flux setups, sync policies, drift detection, promotion, rollback, app-of-apps, secrets, cluster access, and deployment governance.

- `aiops-signal-correlation-reviewer.prompt.md` — Assess correlation of logs, metrics, traces, events, and incidents to reduce noise, improve root-cause analysis, and lower alert fatigue.

- `alert-quality-reviewer.prompt.md` — Review alerts for actionability, clear symptoms, runbook links, severity, ownership, SLO relation, deduplication, escalation, and remediation suitability.

- `auto-remediation-reviewer.prompt.md` — Review automated repair actions for safe limits, dry runs, approval modes, rollback, audit logs, blast radius, and loop protection.

- `mlops-governance-reviewer.prompt.md` — Review model versioning, training data, bias, drift, monitoring, approvals, reproducibility, model registry, and deployment gates.

- `llmops-security-reviewer.prompt.md` — Review GenAI workloads for prompt injection, tool permissions, data exfiltration, RAG sources, sensitive prompt logging, evals, guardrails, and model access.

- `ai-change-risk-reviewer.prompt.md` — Review AI-assisted changes before execution for automation boundaries, human approval, affected-system criticality, and audit evidence.

- `privacy-data-protection-reviewer.prompt.md` — Review privacy, personal data, data classification, deletion concepts, purpose limitation, GDPR risks, and sensitive-data logging.

- `api-contract-reviewer.prompt.md` — Review REST, GraphQL, OpenAPI, and gRPC contracts, breaking changes, versioning, AuthN/AuthZ, error formats, and compatibility.

- `secure-design-reviewer.prompt.md` — Review secure-by-design decisions, least privilege, Zero Trust, tenant separation, secure defaults, and abuse scenarios.

- `policy-as-code-reviewer.prompt.md` — Review GitLab Security Policies, OPA/Rego, Kyverno, Conftest, Sentinel, admission policies, compliance pipelines, and central guardrails.

- `container-security-reviewer.prompt.md` — Review Dockerfiles, base images, user rights, capabilities, SBOM, image signing, distroless or slim images, CVEs, and runtime hardening.

- `identity-access-reviewer.prompt.md` — Review IAM, roles, service accounts, groups, tokens, OIDC federation, GitLab or GitHub permissions, cloud rights, and privilege-escalation paths.

- `risk-acceptance-reviewer.prompt.md` — Document and assess conscious risk decisions, impact and likelihood, expiry dates, and compensating measures.

- `secure-code-reviewer.prompt.md` — Review code vulnerabilities such as injection, path traversal, SSRF, XSS, deserialization, crypto misuse, and race conditions.

- `performance-scalability-reviewer.prompt.md` — Review load behavior, bottlenecks, caching, database access, queue behavior, scaling, timeouts, and resource limits.

- `migration-change-reviewer.prompt.md` — Review database migrations, schema changes, breaking changes, rollback ability, backward compatibility, and zero-downtime deployments.

- `sbom-vulnerability-management-reviewer.prompt.md` — Review SBOM generation, CVE triage, VEX, exception processes, patch SLAs, and the vulnerability lifecycle.

- `developer-experience-reviewer.prompt.md` — Review setup, local development, error messages, Makefiles or scripts, onboarding, tooling consistency, and practicality for teams.

- `resilience-reviewer.prompt.md` — Review timeouts, retries, circuit breakers, failover, backpressure, degraded modes, and resilience behavior.

- `backup-restore-reviewer.prompt.md` — Review restore tests, RPO/RTO, data integrity, backup protection, recoverability, and disaster recovery.


## Required behavior

- Prefer minimal, reviewable changes.
- Do not expose secrets or credentials.
- Do not change CI/CD or security posture without explaining the impact.
- Run or suggest repository-native validation.
- Summarize changed files, validation, and risks.
