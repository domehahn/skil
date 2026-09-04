# Skill Registry Duplicate Intelligence & Admission Control

SKIL includes a multi-stage **Skill Duplicate Intelligence and Registry Admission Control** subsystem. This subsystem prevents redundant, duplicate, near-duplicate, or subset skills from being published into a Skill Registry while still permitting legitimate specializations, extensions, supersets, and complementary skills.

Rather than relying on simple string matching, SKIL treats duplicate detection as a multi-stage governance problem combining canonical fingerprinting, capability overlap analysis, semantic vector similarity, and policy-driven admission decisions.

---

## Architecture Overview

```text
                       Candidate Skill
                             │
                             ▼
                  ┌────────────────────┐
                  │ Schema Validation  │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │ Canonical SHA-256  │
                  │ Fingerprinting     │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │ Name & Metadata    │
                  │ Similarity         │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │ Capability         │
                  │ Fingerprinting     │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │ Semantic Similarity│
                  │ Engine             │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │ Relationship       │
                  │ Classification     │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │ Optional LLM Judge │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │ Admission Policy   │
                  └─────────┬──────────┘
                            │
                 ┌──────────┼──────────┐
                 ▼          ▼          ▼
              REJECT      REVIEW     ACCEPT
```

---

## Relationship Classification Model

SKIL classifies duplicate relationships into ten explicit governance categories:

| Relationship | Description | Default Decision |
|---|---|---|
| `EXACT_DUPLICATE` | Canonical SHA-256 fingerprint matches an existing skill 100%. | `REJECT` |
| `SEMANTIC_DUPLICATE` | Wording differs, but purpose and capabilities match (≥95% similarity, ≥90% capability overlap). | `REJECT` |
| `HIGH_SIMILARITY` | Strong overall functional overlap requiring human review (≥90% similarity). | `REVIEW` |
| `CAPABILITY_OVERLAP` | Substantial shared capabilities across actions/tools (≥70% overlap). | `REVIEW` |
| `SUBSET` | Candidate is a strict subset of an existing skill's capabilities. | `REJECT` |
| `SUPERSET` | Candidate extends an existing skill with unique new capabilities. | `REVIEW` |
| `COMPLEMENTARY` | Same domain, but performs a distinct complementary task. | `ACCEPT` |
| `RELATED` | Related domain or general purpose with distinct implementation. | `ACCEPT` |
| `DISTINCT` | No meaningful duplicate relationship found. | `ACCEPT` |
| `UNKNOWN` | Insufficient data to determine relationship safely. | `REVIEW` |

---

## Canonical SHA-256 Fingerprinting

To prevent simple formatting variations from bypassing duplicate checks, SKIL canonicalizes skills before hashing:

1. **Path Normalization**: Replaces Windows backslashes (`\`) with forward slashes (`/`).
2. **Line Ending Normalization**: Converts all line endings (`\r\n` and `\r`) to `\n`.
3. **Deterministic Ordering**: Sorts all file paths alphabetically.
4. **Transient Filtering**: Automatically excludes `.git`, `.DS_Store`, `Thumbs.db`, `node_modules`, `__pycache__`, timestamps, and build temp files.
5. **SHA-256 Digest**: Computes a stable SHA-256 digest over normalized paths and content.

---

## Capability Fingerprinting & Overlap

SKIL extracts normalized technical capability fingerprints from skill manifests (`skil.yaml`), `SKILL.md`, and static analyzer output:

* **Domain**: `kubernetes`, `terraform`, `docker`, `aws`, `slack`, etc.
* **Actions**: `deploy`, `rollback`, `canary`, `health-check`, `scan`, `audit`, etc.
* **Tools**: `kubectl`, `helm`, `docker`, `terraform`, `yara`, `trivy`, etc.
* **Resources**: `deployment`, `service`, `ingress`, `secret`, `cluster`, etc.
* **Permissions**: `cluster-write`, `cluster-read`, `shell`, `network`, etc.

### Synonym Normalization
Synonyms are automatically mapped to canonical forms:
* `k8s` → `kubernetes`
* `kubectl apply` / `helm install` → `deploy`
* `docker build` → `build`

### Directional Containment
SKIL calculates directional containment to distinguish `SUBSET` (candidate capabilities ⊆ existing) from `SUPERSET` (existing capabilities ⊆ candidate).

---

## Semantic Similarity & Offline Operations

SKIL supports multiple semantic similarity providers through a unified provider interface:

* **`local-tfidf` (Default)**: 100% offline local TF-IDF n-gram vectorizer with cosine similarity. Zero external SaaS dependencies or API keys required.
* **SaaS/HTTP Adapters**: Support for OpenAI-compatible, Ollama-compatible, and NVIDIA SkillEvaluator embedding endpoints with automatic fallback to local provider on error.
* **Embedding Cache**: Caches vector embeddings keyed by `sha256(fingerprint + provider + model + rep_mode)` for sub-millisecond retrieval.

---

## CLI Reference

### `skil registry check <skill>`
Check a candidate skill against the registry catalog before publishing:

```bash
skil registry check ./skills/my-skill --catalog .skil/catalog.json
```

Output example:

```text
SKIL Registry Admission Check
────────────────────────────────────────────────────────────
Candidate:    kubernetes-deployment
Most Similar: kubernetes-deployer
Relationship: SUPERSET
Decision:     REVIEW

Similarity Breakdown:
  Semantic:     94%
  Capability:   91%
  Name:         85%

Reason:
  Candidate significantly extends existing skill "kubernetes-deployer" with 3 unique capabilities.

Recommendation:
  Consider integrating candidate capabilities into "kubernetes-deployer" or publishing as a specialized extension.
```

Flags:
* `--catalog <file>`: Path to catalog JSON file (default `.skil/catalog.json`).
* `--namespace <ns>`: Scope search to a specific tenant/namespace.
* `--format terminal|json|sarif`: Output format.
* `--fail-on reject|review|duplicate`: Control CI failure exit code threshold.
* `--policy <file>`: Custom policy YAML configuration.

### `skil registry index <directory>`
Index a skill directory or collection into the registry catalog:

```bash
skil registry index .agents/skills --catalog .skil/catalog.json
```

### `skil registry list`
List all indexed skills in the catalog:

```bash
skil registry list --catalog .skil/catalog.json
```

### `skil registry search <query>`
Perform semantic discovery search across the catalog:

```bash
skil registry search "deploy applications into kubernetes" --catalog .skil/catalog.json
```

### `skil registry compare <candidate> <existing>`
Perform a side-by-side capability and similarity comparison between two skills:

```bash
skil registry compare ./candidate-skill ./existing-skill
```

---

## Admission Policy & Suppressions

Configure admission rules and policy exceptions in `.skil/config.yaml` or a policy file:

```yaml
registry:
  admission:
    enabled: true
    thresholds:
      exact_action: reject
      semantic_duplicate: 0.95
      semantic_high_similarity: 0.90
      capability_duplicate: 0.90
      capability_subset: 0.90
      capability_superset: 0.90

    policies:
      exact_duplicate: reject
      semantic_duplicate: reject
      high_similarity: review
      capability_overlap: review
      subset: reject
      superset: review
      complementary: accept
      distinct: accept

    allow:
      - candidate: k8s-prod-deployer
        related_to: kubernetes-deployer
        reason: "Approved hardened production specialization"
        owner: "platform-team"
```

---

## Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Candidate ADMITTED (`ACCEPT` or `ACCEPT_WITH_WARNING`). |
| `1` | Command execution error, invalid input, or tool failure. |
| `2` | Candidate REJECTED (`REJECT` due to exact/semantic duplicate or subset). |
| `3` | Candidate requires MANUAL REVIEW (`REVIEW` due to superset or high similarity). |

---

## CI/CD Pipeline Integration

### GitHub Actions

```yaml
name: Skill Admission Gate
on: [push, pull_request]

jobs:
  admission-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Build skil
        run: go build -o bin/skil ./cmd/skil
      - name: Check Registry Admission
        run: |
          bin/skil registry check ./my-skill \
            --catalog .skil/catalog.json \
            --fail-on reject \
            --format sarif --output registry-admission.sarif
```

### GitLab CI

```yaml
skill-registry-admission:
  stage: test
  script:
    - skil registry check ./my-skill --catalog .skil/catalog.json --fail-on reject
  artifacts:
    reports:
      codequality: registry-admission.json
```

---

## Security & Prompt Injection Protection

1. **Data-Not-Instruction Boundary**: Candidate `SKILL.md` content and prompt text are strictly treated as untrusted data inputs. Structured XML/JSON delimiters prevent candidate text from altering LLM judge system rules or governance control flow.
2. **Static Analysis Only**: No candidate scripts or executable code are invoked during duplicate analysis.
3. **Path Confinement**: All catalog file reads and workspace scans enforce strict root directory boundary checks.
