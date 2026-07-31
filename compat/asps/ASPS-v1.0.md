# Agent Skill Security Properties Specification (ASPS) v1.0

**Status:** Proposed open taxonomy / working specification  
**Sprache:** Deutsch  
**Snapshot:** 31. Juli 2026  
**Scope:** Wiederverwendbare Agent Skills (`SKILL.md` + Metadaten + Code + Ressourcen + Tools + Dependencies + Runtime-Wirkung)  
**Normativer Status:** Nicht OWASP, MITRE, NIST oder MCP. ASPS ist eine eigenständige Synthese mit expliziten Crosswalks.

## 1. Ziel und Begriffsmodell

ASPS definiert Security Properties als **prüfbare Invarianten**. Die Spezifikation trennt bewusst fünf Ebenen:

```text
Threat / Risk
    ↓
Security Property / Invariant
    ↓
Required Evidence
    ↓
Detection / Verification Mechanism
    ↓
Concrete Control / Rule
```

Ein Analyseverfahren wie **Taint Tracking**, **AST Analysis**, **YARA**, **Unicode Analysis** oder **OSV** ist daher nicht selbst die Security Property.

### 1.1 Formales Skill-Modell

Angelehnt an die aktuelle Skill-Security-Forschung wird ein Skill als

```text
S = (M, W, P, T, V)
```

modelliert:

- `M`: semantische Metadaten und Beschreibung,
- `W`: Workflow, Instruktionen und ausführbares Verhalten,
- `P`: Permissions und deklarierte Capabilities,
- `T`: Tools, MCP-Server und externe Services,
- `V`: Version, Provenance und Identität.

Zur Laufzeit ergänzen wir `I` (Identity), `C` (Context), `Σ` (State/Memory) und `E` (Environment).

Eine Security Property ist ein Prädikat:

```text
φᵢ(S, I, C, Σ, E) ∈ {true, false, unknown}
```

Ein Finding ist nur dann belastbar, wenn Evidence eine Verletzung `¬φᵢ` stützt. Ein Scanner darf `unknown` nicht in `true` umdeuten.

## 2. Normative Sprache

- **MUSS / MUST**: erforderlich für Konformität.
- **DARF NICHT / MUST NOT**: verboten.
- **SOLLTE / SHOULD**: starke Empfehlung; Abweichung benötigt dokumentierte Begründung.
- **KANN / MAY**: optional.

## 3. Evidence-Klassen

| Klasse | Beispiele | Charakter |
|---|---|---|
| Lexical/Intent | Modalität, Negation, Instruktionsrelation | probabilistisch bis deterministisch |
| Structural | YAML, JSON, Frontmatter, Manifest, Lockfile | hoch deterministisch |
| AST | Python, JS/TS, Bash Syntax Tree | hoch deterministisch |
| CFG/Dataflow | erreichbare Kontroll- und Datenpfade | strukturell |
| Taint | Source → Propagation → Sink | kausal, pfadabhängig |
| Identity/Auth | Token, Scope, Audience, Signer | hoch deterministisch |
| Cryptographic | Digest, Signatur, Attestation | sehr hoch deterministisch |
| Dependency | Package, Version, Advisory, Registry | abhängig von Resolution/Evidence |
| Runtime | Process, File, Network, Tool Trace | hoch für beobachtete Pfade |
| Semantic | Description↔Behavior, Goal Drift, Camouflage | probabilistisch |

## 4. Coverage-Zustände

```text
VERIFIED
VIOLATED
PARTIALLY_VERIFIED
RUNTIME_DEPENDENT
SEMANTIC_ONLY
NOT_OBSERVABLE
PROVIDER_UNAVAILABLE
```

**Kein Finding ist nicht gleich `VERIFIED`.**

## 5. Top-Level-Taxonomie


| Domain | Name | Zweck | Properties |
|---|---|---|---:|
| ASP-01 | Instruction & Goal Integrity | Schützt Instruktionshierarchie, autorisierten Auftrag und semantische Steuerung des Agenten. | 8 |
| ASP-02 | Discovery, Metadata & Selection Integrity | Schützt Admission, Retrieval und Planner-Auswahl vor Metadaten-, Ranking- und Reputationsmanipulation. | 8 |
| ASP-03 | Data Confidentiality & Privacy | Begrenzt Zugriff, Nutzung, Speicherung und Übertragung sensitiver Daten auf den legitim benötigten Umfang. | 8 |
| ASP-04 | Identity, Authorization & Consent | Sichert nicht-menschliche Identitäten, Berechtigungen, Delegation, Token-Grenzen und Zustimmung. | 8 |
| ASP-05 | Tool, Capability & Agency Safety | Begrenzt Tool-Nutzung, Parameter, Komposition und autonome Seiteneffekte. | 8 |
| ASP-06 | Code Execution & Information-Flow Safety | Schützt Interpreter-, Prozess-, Shell- und Output-Grenzen und erzwingt nachvollziehbaren Datenfluss. | 8 |
| ASP-07 | Memory, State & Persistence Integrity | Schützt persistente und temporäre Zustände vor Vergiftung, Übernahme, Überfüllung und unerlaubter Lebensdauer. | 8 |
| ASP-08 | Inter-Agent & Delegation Security | Sichert Agent-zu-Agent-Kommunikation, Delegation und zusammengesetzte Workflows. | 8 |
| ASP-09 | Supply Chain, Provenance & Artifact Integrity | Sichert Publisher, Signatur, Version, Update und Review-to-Execution-Kontinuität des Skill-Artefakts. | 8 |
| ASP-10 | MCP & Integration Protocol Security | Überträgt Skill-Sicherheitsinvarianten auf MCP-Metadaten, Tool-Identitäten, OAuth und lokale Integrationen. | 8 |
| ASP-11 | Network, Filesystem & Runtime Boundary Security | Schützt Host-, Netzwerk-, Container- und Nachbar-Skill-Grenzen. | 8 |
| ASP-12 | Resource, Availability & Failure Containment | Begrenzt Kosten, Endlosschleifen, Ressourcenverbrauch und kaskadierende Fehlwirkungen. | 8 |
| ASP-13 | Human-Agent Trust & Safety | Schützt Nutzer vor Täuschung, Consent-Laundering, gefährlichen Operationszielen und unkritischem Vertrauen in Agentenausgaben. | 8 |
| ASP-14 | Auditability, Observability & Accountability | Macht Skill-Entscheidungen und Wirkungen sicherheitsrelevant nachvollziehbar, ohne private Chain-of-Thought zu verlangen. | 8 |
| ASP-15 | Dependency, Package & Container Supply-Chain Security | Behandelt klassische Software-Supply-Chain-Risiken innerhalb von Skills als eigenständige Properties statt als Analyzer-Namen. | 8 |

**Gesamt:** 15 Domänen, 120 Security Properties.

## 6. Crosswalk: OWASP Top 10 for Agentic Applications 2026

| OWASP | Risk | Primäre ASPS-Domains |
|---|---|---|
| ASI01 | Agent Goal Hijack | ASP-01, ASP-02, ASP-06 |
| ASI02 | Tool Misuse & Exploitation | ASP-03, ASP-05, ASP-06, ASP-10, ASP-11, ASP-12 |
| ASI03 | Identity & Privilege Abuse | ASP-04, ASP-08, ASP-10, ASP-11, ASP-14 |
| ASI04 | Agentic Supply Chain Vulnerabilities | ASP-02, ASP-09, ASP-10, ASP-15 |
| ASI05 | Unexpected Code Execution | ASP-05, ASP-06, ASP-11, ASP-15 |
| ASI06 | Memory & Context Poisoning | ASP-03, ASP-07 |
| ASI07 | Insecure Inter-Agent Communication | ASP-04, ASP-08, ASP-10, ASP-14 |
| ASI08 | Cascading Failures | ASP-08, ASP-12, ASP-14 |
| ASI09 | Human-Agent Trust Exploitation | ASP-01, ASP-02, ASP-13 |
| ASI10 | Rogue Agents | ASP-01, ASP-05, ASP-07, ASP-08, ASP-09, ASP-12, ASP-13, ASP-14 |

## 7. Property Registry

Die `skil`-Spalte ist ein **Roadmap-Crosswalk**, keine Konformitätszertifizierung:

- `IMPLEMENTED`: Kern der Invariante besitzt einen aktuellen nativen Control.
- `PARTIAL`: relevante Evidenz vorhanden, aber nicht die vollständige Invariante.
- `NEW`: kein dedizierter aktueller Control identifiziert.
- `PROVIDER_BACKED`: belastbare Aussage hängt von externer/optionaler Evidenz ab.


# ASP-01 — Instruction & Goal Integrity

Schützt Instruktionshierarchie, autorisierten Auftrag und semantische Steuerung des Agenten.

**Primärer Crosswalk:** OWASP Agentic ASI01, ASI09, ASI10; OWASP LLM LLM01, LLM06, LLM07; MITRE ATLAS LLM Prompt Injection, LLM Jailbreak, AI Agent Context Poisoning, Modify AI Agent Configuration.

## ASP-01.01 — Instruction Hierarchy Preservation

**Normative Invariante:** Höher priorisierte System-, Developer- und Policy-Instruktionen dürfen durch Skill-Inhalte weder explizit noch semantisch überschrieben, entwertet oder ersetzt werden.

**Detection/Verification:** Pattern-/Intent-Analyse mit Negationsscope; semantische Residualanalyse; Runtime-Policy.

**Mindest-Evidence:** Override-Operation, Target, Modalität, Scope und Kontext.

**Aktuelles `skil`-Mapping:** `SKIL-PI-001` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-01.02 — Role & Context Integrity

**Normative Invariante:** Ein Skill darf weder eine privilegiertere Rolle vortäuschen noch untrusted Inhalt in einen höher vertrauenswürdigen Kontext umklassifizieren.

**Detection/Verification:** Rollen-/Kontext-Token-Erkennung, semantische Rollenrelation, Trust-Label-Propagation.

**Mindest-Evidence:** Actor, beanspruchte Rolle, ursprüngliche Trust-Klasse und Kontextwechsel.

**Aktuelles `skil`-Mapping:** `SKIL-PI-002`, `SKIL-PI-003` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-01.03 — Refusal Preservation

**Normative Invariante:** Ein Skill darf die Fähigkeit des Agenten, unzulässige oder nicht verifizierbare Aktionen abzulehnen, nicht generell unterdrücken.

**Detection/Verification:** Intent- und Modalitätsanalyse für REFUSE/COMPLY.

**Mindest-Evidence:** actor=AGENT; action=REFUSE; permission=FORBIDDEN bzw. unconditional compliance.

**Aktuelles `skil`-Mapping:** `SKIL-INTENT-REFUSAL` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-01.04 — Warning & Safety-Context Preservation

**Normative Invariante:** Ein Skill darf notwendige Warnungen, Caveats oder sicherheitsrelevante Hinweise nicht pauschal unterdrücken.

**Detection/Verification:** Intent-Analyse für Suppression-Verben und Safety-Objekte.

**Mindest-Evidence:** Suppression-Intent, Safety-Objekt, Scope und Kontext.

**Aktuelles `skil`-Mapping:** `SKIL-INTENT-WARNING` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-01.05 — Guardrail Integrity

**Normative Invariante:** Ein Skill darf Sicherheitsrichtlinien, Guardrails oder Policy-Enforcement nicht als unwirksam, optional oder deaktivierbar deklarieren.

**Detection/Verification:** Guardrail-Nullification-Patterns plus semantische Policy-Relation.

**Mindest-Evidence:** Guardrail/Policy als Target, Nullification-Operation und Reichweite.

**Aktuelles `skil`-Mapping:** `SKIL-INTENT-GUARDRAIL`, `SKIL-GUARDRAIL-I18N-001` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-01.06 — Hidden Instruction Resistance

**Normative Invariante:** Instruktionen dürfen nicht durch unsichtbare Unicode-Zeichen, Bidi-Steuerung, Kommentar-/Rendering-Differenzen oder Darstellungsasymmetrien verborgen werden.

**Detection/Verification:** Unicode-Codepoint-, Bidi-, Markdown/HTML- und Render-vs-Raw-Analyse.

**Mindest-Evidence:** Raw codepoints/markup, versteckte Instruktionsspanne und Render-Differenz.

**Aktuelles `skil`-Mapping:** `SKIL-UNI-001`, `SKIL-UNI-003` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-01.07 — Covert Behavioral Steering Resistance

**Normative Invariante:** Ein Skill darf Nutzer- oder Agentenentscheidungen nicht verdeckt zugunsten fremder Ziele oder Sicherheitsabsenkungen steuern.

**Detection/Verification:** Intent-Analyse für biased recommendation, concealment, trust-then-exploit und safety-deprioritization.

**Mindest-Evidence:** Steering-Ziel, Begünstigter und manipulierte Entscheidung.

**Aktuelles `skil`-Mapping:** `SKIL-INTENT-BEHAVIOR-MANIPULATION` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-01.08 — Goal & Scope Integrity

**Normative Invariante:** Der effektive Skill-Auftrag und daraus abgeleitete Subziele müssen innerhalb des autorisierten Scopes bleiben.

**Detection/Verification:** Contract-vs-Behavior-Diff, semantische Goal-Relation und Runtime-Capability-Checks.

**Mindest-Evidence:** declared_goal, effective_goal, zusätzliche Operation und fehlende Autorisierung.

**Aktuelles `skil`-Mapping:** `SKIL-INTENT-SCOPE` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

# ASP-02 — Discovery, Metadata & Selection Integrity

Schützt Admission, Retrieval und Planner-Auswahl vor Metadaten-, Ranking- und Reputationsmanipulation.

**Primärer Crosswalk:** OWASP Agentic ASI01, ASI04, ASI09; OWASP LLM LLM01, LLM03, LLM06, LLM09; MITRE ATLAS AI Supply Chain Reputation Inflation, AI Supply Chain Rug Pull, Prompt Infiltration via Public-Facing Application.

## ASP-02.01 — Metadata Authenticity

**Normative Invariante:** Name, Beschreibung, Eigentümer-, Herkunfts- und Vertrauensmetadaten müssen nachweisbar zum tatsächlich geladenen Skill-Artefakt gehören.

**Detection/Verification:** Schema-Validierung, Signatur-/Provenance-Bindung, Registry-Abgleich.

**Mindest-Evidence:** Metadatenwert, Artefakt-Digest, Publisher-Identität und Bindungsnachweis.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-02.02 — Description–Behavior Consistency

**Normative Invariante:** Die semantische Beschreibung eines Skills muss seine sicherheitsrelevanten Operationen, Datenflüsse und Capabilities angemessen widerspiegeln.

**Detection/Verification:** Capability-Extraktion plus semantischer Vergleich von Beschreibung und Workflow/Code.

**Mindest-Evidence:** description claims, observed capabilities und Mismatch.

**Aktuelles `skil`-Mapping:** `SKIL-MCP-006`, `SKIL-INTENT-DESCRIPTION`, `SKIL-INTENT-IMPLEMENTATION` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-02.03 — Trigger Specificity

**Normative Invariante:** Aktivierungskriterien müssen hinreichend spezifisch sein und dürfen nicht nahezu jeden Request matchen.

**Detection/Verification:** Strukturelle Trigger-Auswertung, Stopword-/Längenregeln, semantische Spezifität.

**Mindest-Evidence:** Triggerwert, Matching-Breite und Konfliktmenge.

**Aktuelles `skil`-Mapping:** `SKIL-TRIGGER-GENERIC`, `SKIL-TA-001` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-02.04 — Trigger Shadowing Resistance

**Normative Invariante:** Ein Skill darf keine Built-in-Kommandos, anderen Skills oder Kontrollpfade durch kollidierende Trigger abfangen oder ersetzen.

**Detection/Verification:** Set-Membership gegen reservierte Trigger, Namespace-Analyse, Registry-Diff.

**Mindest-Evidence:** Trigger, kollidierende Identität und Routingpriorität.

**Aktuelles `skil`-Mapping:** `SKIL-TRIGGER-SHADOW` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-02.05 — Retrieval Keyword-Stuffing Resistance

**Normative Invariante:** Skill-Metadaten dürfen semantisches Retrieval nicht durch künstliche Keyword-Dichte manipulieren.

**Detection/Verification:** Term-Density, Repetition Metrics, embedding-vs-content consistency, adversarial retrieval tests.

**Mindest-Evidence:** überrepräsentierte Tokens, Ranking-Delta und funktionale Entsprechung.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-02.06 — Semantic Camouflage Resistance

**Normative Invariante:** Riskantes Verhalten darf sich nicht allein durch semantisch passende, aber verharmlosende Beschreibung als legitimer Kandidat tarnen.

**Detection/Verification:** Metadata-to-workflow consistency, capability diff und anomaly scoring.

**Mindest-Evidence:** Retrieval-Relevanz bei gleichzeitigem Behavior-Mismatch.

**Aktuelles `skil`-Mapping:** `SKIL-SEM-SECURITY`, `SKIL-INTENT-DESCRIPTION` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-02.07 — Sybil & Reputation Manipulation Resistance

**Normative Invariante:** Clone-Skills, Publisher-Sybil-Identitäten oder erfundene Vertrauenssignale dürfen Ranking und Auswahl nicht künstlich dominieren.

**Detection/Verification:** Near-duplicate clustering, publisher graph analysis, signed reputation provenance und diversity filtering.

**Mindest-Evidence:** Clone-Cluster, Publisher-Beziehungen, Reputationsevidence und Ranking-Effekt.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-02.08 — Planner Selection Integrity

**Normative Invariante:** Der Planner darf Skills nur anhand verifizierter Metadaten, Capabilities und Vertrauenssignale auswählen; Fake Recommendations und Permission Deception dürfen die Auswahl nicht dominieren.

**Detection/Verification:** Metadata sanitization, planner adversarial tests, permission consistency, trust-aware reranking.

**Mindest-Evidence:** Candidate set, Planner-Entscheidung und manipulierendes Metadatum.

**Aktuelles `skil`-Mapping:** `SKIL-INTENT-DESCRIPTION`, `SKIL-CAP-DECLARATION-MISSING` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

# ASP-03 — Data Confidentiality & Privacy

Begrenzt Zugriff, Nutzung, Speicherung und Übertragung sensitiver Daten auf den legitim benötigten Umfang.

**Primärer Crosswalk:** OWASP Agentic ASI01, ASI02, ASI03, ASI06, ASI07; OWASP LLM LLM02, LLM06, LLM07; MITRE ATLAS Exfiltration via AI Agent Tool Invocation, Extract LLM System Prompt, AI Agent Tool Credential Harvesting.

## ASP-03.01 — Secret & Environment Harvesting Protection

**Normative Invariante:** Secrets, Tokens und sensitive Environment-Variablen dürfen nur bei explizit autorisiertem Zweck und Scope gelesen werden.

**Detection/Verification:** Credential pattern detection, AST env access, capability verification, secret-source taint.

**Mindest-Evidence:** konkrete Secret-Quelle, Read-Operation, Zweck und downstream flow.

**Aktuelles `skil`-Mapping:** `SKIL-SEC-001`, `SKIL-TAINT-NETWORK` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-03.02 — Credential File Protection

**Normative Invariante:** Credential-bearing Dateien und Stores dürfen nicht opportunistisch gesucht, gelesen, kopiert oder exportiert werden.

**Detection/Verification:** Pfadklassifikation, Filesystem AST/pattern analysis und defensive context suppression.

**Mindest-Evidence:** Credential-Pfad, Operation, Scope und Verwendungsziel.

**Aktuelles `skil`-Mapping:** `SKIL-SEC-001` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-03.03 — Conversation & Context Confidentiality

**Normative Invariante:** Konversationsverlauf, Agentenstatus, Memory und Session-Kontext dürfen nicht ohne Zweckbindung offengelegt oder übertragen werden.

**Detection/Verification:** Context-object classification, exfil intent, taint and sink analysis.

**Mindest-Evidence:** Context source, Transformation, Sink und Authorization.

**Aktuelles `skil`-Mapping:** `SKIL-EX-001`, `SKIL-INTENT-EXTERNAL-TRANSFER` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-03.04 — Privileged Instruction Confidentiality

**Normative Invariante:** System-/Developer-Prompts und interne Instruktionen dürfen weder direkt, indirekt noch über Tools extrahiert werden.

**Detection/Verification:** Direct/indirect leakage patterns, transform-aware semantic analysis und prompt-source taint.

**Mindest-Evidence:** privileged prompt source, extraction operation, transform und sink.

**Aktuelles `skil`-Mapping:** `SKIL-PL-001`, `SKIL-PROMPT-INDIRECT-LEAK` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-03.05 — External Data Exfiltration Prevention

**Normative Invariante:** Sensitive Daten dürfen keine nicht autorisierten externen Netzwerk-, Tool- oder Logging-Sinks erreichen.

**Detection/Verification:** Source/sink taint, URL/domain classification, network AST und intent analysis.

**Mindest-Evidence:** Source→Propagation→Sink-Pfad sowie Destination trust.

**Aktuelles `skil`-Mapping:** `SKIL-EX-001`, `SKIL-NET-001`, `SKIL-TAINT-NETWORK`, `SKIL-INTENT-EXTERNAL-TRANSFER` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-03.06 — Cloud/Object-Storage Exfiltration Prevention

**Normative Invariante:** Uploads in S3-, GCS-, Azure- oder vergleichbare Stores müssen explizit autorisierte Daten und Ziele betreffen.

**Detection/Verification:** Cloud CLI/SDK recognition, bucket/container classification und taint.

**Mindest-Evidence:** Upload call, Ziel, Source-Daten und Authorization evidence.

**Aktuelles `skil`-Mapping:** `SKIL-BOUNDARY-CLOUD-EXFIL`, `SKIL-BOUNDARY-CLOUD-SDK-UPLOAD` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-03.07 — Data Minimization

**Normative Invariante:** Ein Skill darf nur Datenklassen und Datenbereiche lesen, die für seinen deklarierten Zweck erforderlich sind.

**Detection/Verification:** Contract-to-observed-read comparison, data/path scopes und runtime access policy.

**Mindest-Evidence:** required data set versus observed access set.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-03.08 — Purpose & Retention Bound

**Normative Invariante:** Erhobene Daten dürfen weder für neue Zwecke umgewidmet noch länger oder persistenter gespeichert werden als autorisiert.

**Detection/Verification:** Data lineage labels, state-write analysis, retention metadata und runtime policy.

**Mindest-Evidence:** data class, original purpose, new purpose/store und retention lifetime.

**Aktuelles `skil`-Mapping:** `SKIL-MP-001`, `SKIL-PERSISTENCE-STARTUP` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

# ASP-04 — Identity, Authorization & Consent

Sichert nicht-menschliche Identitäten, Berechtigungen, Delegation, Token-Grenzen und Zustimmung.

**Primärer Crosswalk:** OWASP Agentic ASI02, ASI03, ASI07; OWASP LLM LLM02, LLM06; MITRE ATLAS Valid Accounts, AI Agent Tool Credential Harvesting, Modify AI Agent Configuration.

## ASP-04.01 — Least-Privilege Permission Bound

**Normative Invariante:** Deklarierte und effektive Berechtigungen müssen auf die minimal für den Skill-Zweck erforderliche Menge beschränkt sein.

**Detection/Verification:** Permission schema analysis, capability observation und contract verification.

**Mindest-Evidence:** requested permissions, observed needs, excess set.

**Aktuelles `skil`-Mapping:** `SKIL-AGENCY-TOOLS`, `SKIL-MCP-001` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-04.02 — Underdeclared Capability Detection

**Normative Invariante:** Jede tatsächlich genutzte sicherheitsrelevante Capability muss im überprüften Skill-Vertrag oder Manifest enthalten sein.

**Detection/Verification:** Observed-capability extraction plus set difference against declarations.

**Mindest-Evidence:** observed capability minus declared capability.

**Aktuelles `skil`-Mapping:** `SKIL-CAP-DECLARATION-MISSING`, `SKIL-CAP-001` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-04.03 — Overdeclared Capability Minimization

**Normative Invariante:** Deklarierte Capabilities ohne nachvollziehbare Nutzung oder Zweckbezug müssen entfernt oder separat gerechtfertigt werden.

**Detection/Verification:** Reverse capability diff, usage observations und reviewer-approved exceptions.

**Mindest-Evidence:** declared capability minus justified/observed capability.

**Aktuelles `skil`-Mapping:** `SKIL-CAP-001` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-04.04 — Approval & Confirmation Integrity

**Normative Invariante:** High-impact Aktionen dürfen erforderliche Approval-Gates nicht umgehen, auto-approven oder durch generische Vorabzustimmung legitimieren.

**Detection/Verification:** Intent patterns, action classification und runtime pre-action policy.

**Mindest-Evidence:** high-impact action, required approval, actual approval state.

**Aktuelles `skil`-Mapping:** `SKIL-AGENCY-APPROVAL` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-04.05 — Credential Scope Minimization

**Normative Invariante:** Tokens und Service-Identitäten müssen kleinste notwendige Scopes, Rollen und Ressourcenbereiche tragen.

**Detection/Verification:** OAuth/IAM scope analysis, policy linting und requested-vs-required comparison.

**Mindest-Evidence:** token scopes/roles, required operation set und excess privileges.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-04.06 — Token Audience & Resource Binding

**Normative Invariante:** Credentials dürfen nur an der Resource verwendet werden, für die sie ausgestellt und vorgesehen wurden.

**Detection/Verification:** JWT/audience/resource validation und downstream call correlation.

**Mindest-Evidence:** issuer, audience/resource, recipient service und mismatch.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-04.07 — Credential Non-Transferability

**Normative Invariante:** User- oder upstream-issued Tokens dürfen nicht ungeprüft an andere Dienste oder MCP-Backends durchgereicht werden.

**Detection/Verification:** Token-passthrough detection, credential taint und proxy boundary analysis.

**Mindest-Evidence:** credential source, intermediary, downstream sink und fehlende exchange/binding.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-04.08 — Revocation & Stop Enforcement

**Normative Invariante:** Entzogene Capabilities, Credentials oder Nutzerfreigaben müssen wirksam unbrauchbar sein; Stop-/Shutdown-Signale müssen zuverlässig greifen.

**Detection/Verification:** Runtime policy, revocation tests, emergency-stop conformance und post-revoke trace validation.

**Mindest-Evidence:** revocation event followed by denied/allowed subsequent action.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

# ASP-05 — Tool, Capability & Agency Safety

Begrenzt Tool-Nutzung, Parameter, Komposition und autonome Seiteneffekte.

**Primärer Crosswalk:** OWASP Agentic ASI02, ASI03, ASI05, ASI10; OWASP LLM LLM05, LLM06; MITRE ATLAS AI Agent Tool Invocation, Command and Scripting Interpreter, Escape to Host.

## ASP-05.01 — Restricted Tool Surface

**Normative Invariante:** Ein Skill darf nicht pauschal alle verfügbaren Tools oder Wildcards erhalten, wenn eine kleinere Tool-Menge genügt.

**Detection/Verification:** Manifest/MCP wildcard checks, natural-language agency patterns und runtime allowlists.

**Mindest-Evidence:** declared tool set, required tool set, wildcard/broad grant.

**Aktuelles `skil`-Mapping:** `SKIL-AGENCY-TOOLS`, `SKIL-MCP-001` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-05.02 — Tool Parameter Safety

**Normative Invariante:** Tool-Parameter müssen typisiert, validiert und gegen Injection, Force-Flags, Path Traversal und semantischen Missbrauch geschützt sein.

**Detection/Verification:** Schema checks, AST/taint, argument semantics und MCP parameter analysis.

**Mindest-Evidence:** tool, parameter, source, validator und dangerous semantic.

**Aktuelles `skil`-Mapping:** `SKIL-PY-002`, `SKIL-TAINT-EXECUTION`, `SKIL-MCP-004` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-05.03 — Tool Chaining Safety

**Normative Invariante:** Eine Sequenz einzeln zulässiger Tools darf keine kombinierte Wirkung erzeugen, die Policy- oder Trust-Grenzen umgeht.

**Detection/Verification:** Shell AST, workflow graph analysis, composite policy und multi-step taint.

**Mindest-Evidence:** ordered tool chain, intermediate artifacts und final privileged sink.

**Aktuelles `skil`-Mapping:** `SKIL-SH-001` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-05.04 — High-Impact Action Gating

**Normative Invariante:** Delete, deploy, publish, send, purchase, privilege change und vergleichbare Aktionen benötigen kontextabhängige Bestätigung oder deterministische Policy.

**Detection/Verification:** Action taxonomy, runtime approval gate und irreversible-effect classifier.

**Mindest-Evidence:** impact class, action parameters und gate decision.

**Aktuelles `skil`-Mapping:** `SKIL-AGENCY-APPROVAL` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-05.05 — Safe Defaults

**Normative Invariante:** Security-relevante Defaults müssen fail-closed sein und TLS, AuthN/AuthZ, Validierung und Schutzmechanismen standardmäßig aktiv lassen.

**Detection/Verification:** Config/pattern analysis, insecure flag detection und policy templates.

**Mindest-Evidence:** default value/flag, affected control und secure alternative.

**Aktuelles `skil`-Mapping:** `SKIL-TRANSPORT-INSECURE` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-05.06 — Capability Scope Confinement

**Normative Invariante:** Eine Capability darf nur auf explizit erlaubte Ziele, Pfade, Hosts, Befehle, Tools und Datenklassen wirken.

**Detection/Verification:** Contract scopes, allowlist matching und runtime policy evaluation.

**Mindest-Evidence:** capability, target, allowed domain und actual target.

**Aktuelles `skil`-Mapping:** `SKIL-CAP-001` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-05.07 — Side-Effect Disclosure

**Normative Invariante:** Sicherheitsrelevante externe Seiteneffekte müssen in Beschreibung/Contract sichtbar und vor Ausführung nachvollziehbar sein.

**Detection/Verification:** Behavior extraction versus metadata/contract diff; explicit silent/covert intent detection.

**Mindest-Evidence:** observed side effect, disclosure location und mismatch.

**Aktuelles `skil`-Mapping:** `SKIL-INTENT-UNDISCLOSED-OPERATION` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-05.08 — Autonomy Bound

**Normative Invariante:** Retry, Rekursion, Delegation, selbständige Folgeaktionen und Entscheidungsfreiheit müssen explizite Grenzen besitzen.

**Detection/Verification:** Resource/agency rule analysis, workflow graph bounds und runtime budgets.

**Mindest-Evidence:** autonomous loop/action, bound und termination condition.

**Aktuelles `skil`-Mapping:** `SKIL-AGENCY-BOUNDS` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

# ASP-06 — Code Execution & Information-Flow Safety

Schützt Interpreter-, Prozess-, Shell- und Output-Grenzen und erzwingt nachvollziehbaren Datenfluss.

**Primärer Crosswalk:** OWASP Agentic ASI02, ASI05; OWASP LLM LLM03, LLM05, LLM06; MITRE ATLAS Command and Scripting Interpreter, Escape to Host, LLM Prompt Obfuscation.

## ASP-06.01 — Dynamic Execution Control

**Normative Invariante:** Dynamisch erzeugte oder untrusted Strings dürfen nicht ungeprüft exec/eval/compile/Reflection oder äquivalente Interpreter-Sinks erreichen.

**Detection/Verification:** Language AST, call resolution, constant propagation und taint.

**Mindest-Evidence:** source expression, propagation path und execution sink.

**Aktuelles `skil`-Mapping:** `SKIL-PY-001`, `SKIL-PY-004`, `SKIL-PY-REFLECT-EXEC` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-06.02 — Process Execution Control

**Normative Invariante:** Subprozesse müssen über sichere argv-Semantik, explizite Programme und validierte Parameter gestartet werden.

**Detection/Verification:** Python/JS AST, subprocess API classification und taint.

**Mindest-Evidence:** process API, executable, argv source und shell mode.

**Aktuelles `skil`-Mapping:** `SKIL-PY-002`, `SKIL-JS-001`, `SKIL-TAINT-EXECUTION` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-06.03 — Shell Execution Safety

**Normative Invariante:** Shell-Syntax aus externen Quellen, Remote-Script-Pipelines und gefährliche Operatoren dürfen keine unkontrollierte Codeausführung ermöglichen.

**Detection/Verification:** Tree-sitter Bash AST, pipeline graph und remote source classification.

**Mindest-Evidence:** shell node, command chain, remote source und sink.

**Aktuelles `skil`-Mapping:** `SKIL-SH-001`, `SKIL-SH-002` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-06.04 — Unsafe Deserialization Control

**Normative Invariante:** Untrusted serialisierte Daten dürfen keine Deserialisierer erreichen, die Objektkonstruktion oder Codeausführung auslösen können.

**Detection/Verification:** AST call classification plus source taint.

**Mindest-Evidence:** deserializer, input source und trust label.

**Aktuelles `skil`-Mapping:** `SKIL-PY-003` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-06.05 — Generated Output Execution Control

**Normative Invariante:** LLM-, Tool- oder Agent-Output darf nicht ohne Validierung als Code, Shell, SQL, Template oder aktive Sprache interpretiert werden.

**Detection/Verification:** Output-source classification, taint to interpreter sinks, improper output patterns.

**Mindest-Evidence:** generated output source, transformation und active sink.

**Aktuelles `skil`-Mapping:** `SKIL-OUTPUT-EXECUTION`, `SKIL-TAINT-EXECUTION` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-06.06 — Cross-Context Output Validation

**Normative Invariante:** Output aus einem niedrigeren Trust-Kontext muss vor Übernahme in Systemprompt, trusted memory, Planner oder anderen Agentenkontext validiert werden.

**Detection/Verification:** Trust-label propagation, boundary rules und structured context sinks.

**Mindest-Evidence:** source context trust, target context trust und validation/declassification.

**Aktuelles `skil`-Mapping:** `SKIL-OUTPUT-BOUNDARY` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-06.07 — Information-Flow Integrity

**Normative Invariante:** Sensitive oder untrusted Daten dürfen nur über erlaubte Transformationen und Declassifier zu sicherheitsrelevanten Sinks gelangen.

**Detection/Verification:** Interprocedural taint/dataflow, CFG/SSA, function summaries und sink-specific sanitizers.

**Mindest-Evidence:** complete source→propagation→sanitizer→sink path.

**Aktuelles `skil`-Mapping:** `SKIL-TAINT-NETWORK`, `SKIL-TAINT-EXECUTION`, `SKIL-TAINT-FILESYSTEM-WRITE`, `SKIL-TAINT-LOG` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-06.08 — Obfuscated & Malicious Payload Safety

**Normative Invariante:** Obfuscation, encoded execution, Malware-Signaturen und selbstentpackende Payloads dürfen Prüfung und Runtime-Grenzen nicht umgehen.

**Detection/Verification:** Entropy/encoding detection, decoded-content scan, YARA, sandbox/detonation und OS-boundary monitoring.

**Mindest-Evidence:** encoded/packed artifact, decoded behavior oder runtime effect.

**Aktuelles `skil`-Mapping:** `SKIL-OBF-001`, `SKIL-YARA-*` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

# ASP-07 — Memory, State & Persistence Integrity

Schützt persistente und temporäre Zustände vor Vergiftung, Übernahme, Überfüllung und unerlaubter Lebensdauer.

**Primärer Crosswalk:** OWASP Agentic ASI06, ASI10; OWASP LLM LLM01, LLM04, LLM06; MITRE ATLAS AI Agent Context Poisoning, Modify AI Agent Configuration, LLM Prompt Self-Replication.

## ASP-07.01 — Memory Poisoning Resistance

**Normative Invariante:** Untrusted Instruktionen dürfen nicht als langfristig vertrauenswürdige Erinnerung oder Verhaltensregel persistiert werden.

**Detection/Verification:** Memory-write intent, trust labels, persistent-state policy und semantic content classification.

**Mindest-Evidence:** untrusted source, memory write und persistence scope.

**Aktuelles `skil`-Mapping:** `SKIL-MP-001` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-07.02 — Context Stuffing Resistance

**Normative Invariante:** Ein Skill darf Kontextfenster nicht absichtlich mit Füll-, Wiederholungs- oder Verdrängungsinhalt dominieren.

**Detection/Verification:** Repetition metrics, token budget analysis und displacement intent.

**Mindest-Evidence:** content volume/repetition, displacement signal und affected context.

**Aktuelles `skil`-Mapping:** `SKIL-MEMORY-SATURATION` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-07.03 — State Manipulation Resistance

**Normative Invariante:** Ein Skill darf Agentenstatus, Konfiguration, gespeicherte Ziele oder Memory nicht außerhalb autorisierter State-APIs und Scopes verändern.

**Detection/Verification:** State sink detection, config diff, persistence boundary und authorization.

**Mindest-Evidence:** state object, mutation, actor und authorization.

**Aktuelles `skil`-Mapping:** `SKIL-MP-001`, `SKIL-AGENT-SELF-MODIFY` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-07.04 — Self-Modification Control

**Normative Invariante:** Ein Skill darf eigene Instruktionen, Code, Policy oder Manifest nur über autorisierte, versionierte und erneut geprüfte Update-Pfade verändern.

**Detection/Verification:** Self-reference/write detection, artifact diff und update pipeline verification.

**Mindest-Evidence:** self-targeted write, changed artifact und revalidation state.

**Aktuelles `skil`-Mapping:** `SKIL-AGENT-SELF-MODIFY` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-07.05 — Persistence Authorization

**Normative Invariante:** Cron, startup services, shell profiles, autorun, background daemons und ähnliche Persistenz müssen explizit deklariert und genehmigt sein.

**Detection/Verification:** Shell/code/config patterns, startup mechanism inventory und contract diff.

**Mindest-Evidence:** persistence mechanism, target und approval.

**Aktuelles `skil`-Mapping:** `SKIL-PERSISTENCE-STARTUP` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-07.06 — State Ownership Isolation

**Normative Invariante:** State handles, files, memory partitions und session-scoped Objekte müssen an die richtige Nutzer-/Agent-/Skill-Identität gebunden bleiben.

**Detection/Verification:** Ownership/access-control checks, state-handle binding und multi-tenant tests.

**Mindest-Evidence:** state identifier, owner identity, caller identity und decision.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-07.07 — Memory Provenance & Trust Labels

**Normative Invariante:** Persistierter Kontext muss Herkunft, Trust-Level und Revalidierungszustand behalten, sodass untrusted Erinnerung später nicht als Systemwissen erscheint.

**Detection/Verification:** Metadata labels, provenance chain und memory retrieval policy.

**Mindest-Evidence:** memory item, origin, trust label und consumer context.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-07.08 — Memory Lifecycle & Expiry

**Normative Invariante:** Temporäre Daten, Zustände und Delegationsinformationen müssen definierte TTL, Lösch- und Invalidierungsregeln besitzen.

**Detection/Verification:** Retention metadata, expiry tests, state inventory und deletion verification.

**Mindest-Evidence:** state item, creation, TTL und deletion/expiry evidence.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

# ASP-08 — Inter-Agent & Delegation Security

Sichert Agent-zu-Agent-Kommunikation, Delegation und zusammengesetzte Workflows.

**Primärer Crosswalk:** OWASP Agentic ASI03, ASI07, ASI08, ASI10; OWASP LLM LLM02, LLM05, LLM06; MITRE ATLAS AI Agent Tool Invocation, AI Agent Tool Data Poisoning, AI Agent Tool Poisoning.

## ASP-08.01 — Agent Identity Authentication

**Normative Invariante:** Nachrichten und Delegationen müssen eindeutig einer authentisierten Agenten-/Service-Identität zuordenbar sein.

**Detection/Verification:** Signed messages, mTLS/OIDC identity validation und registry binding.

**Mindest-Evidence:** sender identity, credential/signature und verifier result.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-08.02 — Inter-Agent Message Integrity

**Normative Invariante:** Agent-zu-Agent-Nachrichten dürfen zwischen Erzeugung und Verarbeitung nicht unbemerkt verändert werden.

**Detection/Verification:** Message signatures/MACs, transport integrity und replay protection.

**Mindest-Evidence:** message digest/signature, sender und receiver.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-08.03 — Delegation Monotonicity

**Normative Invariante:** Ein delegierter Agent darf keine Autorität erhalten, die über die Schnittmenge aus Parent-Autorität und explizit delegiertem Scope hinausgeht.

**Detection/Verification:** Capability algebra, delegation token scopes und runtime authorization.

**Mindest-Evidence:** C_child ⊆ C_parent ∩ C_delegated.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-08.04 — Confused-Deputy Resistance

**Normative Invariante:** Ein privilegierter Agent oder Proxy darf seine Autorität nicht für einen weniger privilegierten oder bösartigen Initiator missbrauchen lassen.

**Detection/Verification:** Initiator binding, per-client consent, audience/scope checks und request provenance.

**Mindest-Evidence:** initiator, deputy, privileged resource und missing binding.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-08.05 — Cross-Agent Trust Propagation Bound

**Normative Invariante:** Unverifizierter Output darf durch Weitergabe über mehrere Agenten nicht automatisch an Trust gewinnen.

**Detection/Verification:** Trust-label propagation across messages und planner contexts.

**Mindest-Evidence:** origin trust, hops, target trust und declassification.

**Aktuelles `skil`-Mapping:** `SKIL-OUTPUT-BOUNDARY` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-08.06 — Inter-Agent Output Validation

**Normative Invariante:** Agentenoutputs müssen am Empfänger wie externe Eingaben behandelt und vor Tool-, Prompt- oder State-Sinks validiert werden.

**Detection/Verification:** Boundary validation, schema checks, taint und intent scanning.

**Mindest-Evidence:** agent output source, receiver sink und validator.

**Aktuelles `skil`-Mapping:** `SKIL-OUTPUT-BOUNDARY`, `SKIL-TAINT-*` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-08.07 — Collusion & Self-Replication Containment

**Normative Invariante:** Mehrere Agenten dürfen durch Koordination, gegenseitige Aktivierung oder Selbstreplikation keine Policies, Quoten oder Takedown-Mechanismen umgehen.

**Detection/Verification:** Graph/rate analysis, identity correlation, propagation detection und runtime quotas.

**Mindest-Evidence:** agent graph, repeated propagation und policy bypass effect.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-08.08 — Delegation Chain Traceability

**Normative Invariante:** Jede delegierte Aktion muss über die gesamte Kette auf Nutzerauftrag, Parent-Agent, Skill, Tool und effektiven Scope zurückführbar sein.

**Detection/Verification:** Distributed trace IDs, signed delegation context und audit correlation.

**Mindest-Evidence:** end-to-end delegation chain with identities and scopes.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

# ASP-09 — Supply Chain, Provenance & Artifact Integrity

Sichert Publisher, Signatur, Version, Update und Review-to-Execution-Kontinuität des Skill-Artefakts.

**Primärer Crosswalk:** OWASP Agentic ASI04, ASI10; OWASP LLM LLM03; MITRE ATLAS AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation.

## ASP-09.01 — Publisher Authenticity

**Normative Invariante:** Ein Skill muss einem erwarteten, überprüfbaren Publisher beziehungsweise Repository-Owner zugeordnet werden können.

**Detection/Verification:** OIDC/code-signing identity, repository ownership und publisher policy.

**Mindest-Evidence:** publisher identity, issuer, repository und verification result.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-09.02 — Artifact Signature Verification

**Normative Invariante:** Veröffentlichte und installierte Skill-Artefakte müssen kryptographisch gegen einen erwarteten Signer verifiziert werden können.

**Detection/Verification:** Detached signature/Sigstore-style verification over the complete artifact closure.

**Mindest-Evidence:** artifact digest, signature, certificate/identity und verification policy.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-09.03 — Payload Integrity

**Normative Invariante:** SKILL.md, Scripts, References, Assets, Hooks und weitere ausführungsrelevante Dateien dürfen nach Signatur/Review nicht verändert werden.

**Detection/Verification:** Merkle/file digest manifest, signature verification und install-time rehash.

**Mindest-Evidence:** reviewed digest set versus installed digest set.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-09.04 — Provenance & Build Attestation

**Normative Invariante:** Die Entstehung des Skills muss über Quelle, Builder, Builddefinition und Inputs nachvollziehbar sein.

**Detection/Verification:** SLSA-style provenance, attestations und source-to-artifact verification.

**Mindest-Evidence:** source URI/digest, builder, build definition und subject digest.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-09.05 — Version Lineage & Rollback Protection

**Normative Invariante:** Installationen und Updates dürfen nicht unbemerkt auf ältere verwundbare oder nicht freigegebene Versionen zurückfallen.

**Detection/Verification:** Monotonic version policy, signed release metadata und rollback denylist.

**Mindest-Evidence:** current version, candidate version, lineage und approval.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-09.06 — Update Revalidation

**Normative Invariante:** Jede neue Skill-Version muss wie ein neuer Admission-Event auf Metadaten, Permissions, Verhalten, Dependencies und Provenance geprüft werden.

**Detection/Verification:** Version diff, semantic behavior diff, capability diff und full rescanning.

**Mindest-Evidence:** old/new artifact, changed security surface und revalidation result.

**Aktuelles `skil`-Mapping:** `SKIL-MCP-005` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-09.07 — Tool & Dependency Substitution Integrity

**Normative Invariante:** Updates dürfen referenzierte Tools, MCP-Server oder Dependencies nicht unbemerkt durch privilegiertere oder andere Identitäten ersetzen.

**Detection/Verification:** Lockfiles, identity pins, dependency graph diff und tool metadata diff.

**Mindest-Evidence:** old/new dependency/tool identities und trust attributes.

**Aktuelles `skil`-Mapping:** `SKIL-MCP-003`, `SKIL-MCP-005` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-09.08 — Review-to-Execution Integrity

**Normative Invariante:** Zur Laufzeit ausgeführte Artefakte müssen innerhalb der geprüften Artifact Closure liegen; TOCTOU-Mutationen sind zu verhindern.

**Detection/Verification:** Digest pinning, immutable mounts, runtime file measurement und sandbox attestation.

**Mindest-Evidence:** review digest, execution digest und mutation/closure evidence.

**Aktuelles `skil`-Mapping:** `SKIL-BOUNDARY-MUTABLE-IMAGE` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

# ASP-10 — MCP & Integration Protocol Security

Überträgt Skill-Sicherheitsinvarianten auf MCP-Metadaten, Tool-Identitäten, OAuth und lokale Integrationen.

**Primärer Crosswalk:** OWASP Agentic ASI02, ASI03, ASI04, ASI07; OWASP LLM LLM03, LLM05, LLM06; MITRE ATLAS AI Agent Tool Poisoning, AI Agent Tool Data Poisoning, AI Agent Tool Credential Harvesting.

## ASP-10.01 — MCP Wildcard Permission Prevention

**Normative Invariante:** MCP-Tool- oder Permission-Listen dürfen keine unbeschränkten Wildcards enthalten, wenn eine konkrete Allowlist möglich ist.

**Detection/Verification:** Structured JSON/YAML schema traversal und set-membership checks.

**Mindest-Evidence:** permission field, wildcard value und available tools.

**Aktuelles `skil`-Mapping:** `SKIL-MCP-001` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-10.02 — MCP Metadata Poisoning Resistance

**Normative Invariante:** Tool-Namen, Beschreibungen, Defaults und andere MCP-Metadaten dürfen keine versteckten oder manipulativen Instruktionen tragen.

**Detection/Verification:** Field-scoped intent analysis, unicode/hidden-content scan und schema parsing.

**Mindest-Evidence:** metadata field/path, malicious span und trust context.

**Aktuelles `skil`-Mapping:** `SKIL-MCP-002`, `SKIL-UNI-001` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-10.03 — MCP Parameter Injection Resistance

**Normative Invariante:** Parameterbeschreibungen und Defaultwerte dürfen keine Prompt-, Shell-, URL- oder Credential-Collection-Payloads enthalten.

**Detection/Verification:** Field-scoped intent engine, length heuristics und URL/shell classification.

**Mindest-Evidence:** parameter field, payload class und matched security relation.

**Aktuelles `skil`-Mapping:** `SKIL-MCP-004`, `SKIL-MCP-007` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-10.04 — MCP Tool Identity Stability

**Normative Invariante:** Tool-/Server-Identität, Command, Args, Schema und sicherheitsrelevante Metadaten müssen an geprüfte Versionen oder Locks gebunden bleiben.

**Detection/Verification:** Identity pinning, lock-file diff, immutable version/digest checks.

**Mindest-Evidence:** reviewed identity versus current identity.

**Aktuelles `skil`-Mapping:** `SKIL-MCP-003`, `SKIL-MCP-005` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-10.05 — MCP Description–Behavior Consistency

**Normative Invariante:** MCP-Toolbeschreibung und beobachtetes Verhalten müssen semantisch und capability-seitig übereinstimmen.

**Detection/Verification:** Code/tool behavior extraction plus semantic comparison.

**Mindest-Evidence:** description, observed operations und mismatch.

**Aktuelles `skil`-Mapping:** `SKIL-MCP-006`, `SKIL-INTENT-DESCRIPTION` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-10.06 — OAuth Authorization URL Safety

**Normative Invariante:** MCP-Clients dürfen nur zulässige Authorization-URL-Schemes und validierte Redirect-Ziele öffnen; Shell-/JS-Schemes und interne Targets sind abzulehnen.

**Detection/Verification:** URL parsing, scheme allowlist, redirect-hop validation und SSRF controls.

**Mindest-Evidence:** authorization URL, scheme, resolved target und validation result.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-10.07 — MCP State-Handle Ownership Binding

**Normative Invariante:** Serverseitige State Handles müssen unvorhersagbar und an die authentisierte Identität beziehungsweise den Mandanten gebunden sein.

**Detection/Verification:** State-handle entropy, ownership authorization und cross-user negative tests.

**Mindest-Evidence:** handle, owner, caller und access result.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-10.08 — Local MCP/stdio Isolation

**Normative Invariante:** Lokale MCP-Server und stdio-Proxies müssen Prozess-, Datei-, Credential- und User-Boundaries wahren und dürfen keine implizite Host-Autorität vererben.

**Detection/Verification:** Process sandbox, executable allowlist, local server provenance und OS-boundary monitoring.

**Mindest-Evidence:** server binary, launch context, inherited privileges und accessible resources.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

# ASP-11 — Network, Filesystem & Runtime Boundary Security

Schützt Host-, Netzwerk-, Container- und Nachbar-Skill-Grenzen.

**Primärer Crosswalk:** OWASP Agentic ASI02, ASI03, ASI05; OWASP LLM LLM02, LLM05, LLM06; MITRE ATLAS Escape to Host, Command and Scripting Interpreter, AI Agent Tool Credential Harvesting.

## ASP-11.01 — Outbound Network Boundary

**Normative Invariante:** Ausgehende Netzwerkverbindungen müssen auf deklarierte Protokolle, Hosts, Ports und Zwecke beschränkt sein.

**Detection/Verification:** Network call inventory, domain/IP allowlists, taint und egress policy.

**Mindest-Evidence:** call, resolved target, purpose und policy result.

**Aktuelles `skil`-Mapping:** `SKIL-NET-001`, `SKIL-TAINT-NETWORK` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-11.02 — Cloud Metadata SSRF Protection

**Normative Invariante:** Link-local und cloud-spezifische Metadata-Endpunkte dürfen nicht über Skill-kontrollierte Requests erreichbar sein.

**Detection/Verification:** Literal endpoint detection, URL resolution, redirect validation und egress block.

**Mindest-Evidence:** request primitive, resolved metadata endpoint und source.

**Aktuelles `skil`-Mapping:** `SKIL-BOUNDARY-METADATA` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-11.03 — Internal & Loopback SSRF Protection

**Normative Invariante:** Requests an localhost, private Netze und interne Services müssen explizit autorisiert und gegen SSRF geschützt sein.

**Detection/Verification:** IP range classification, DNS resolution und redirect-hop validation.

**Mindest-Evidence:** request target, resolved IP/range und trust classification.

**Aktuelles `skil`-Mapping:** `SKIL-BOUNDARY-SSRF-INTERNAL` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-11.04 — Dynamic-Target SSRF Protection

**Normative Invariante:** Untrusted oder dynamisch zusammengesetzte URL-Ziele müssen vor Netzwerkzugriff streng validiert und nach DNS-Auflösung erneut geprüft werden.

**Detection/Verification:** Taint to URL sinks, parser-based validation und DNS pinning/TOCTOU controls.

**Mindest-Evidence:** source variable, URL construction, resolution und network sink.

**Aktuelles `skil`-Mapping:** `SKIL-BOUNDARY-SSRF` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-11.05 — Agent & MCP Configuration Isolation

**Normative Invariante:** Skills dürfen private Agenten-, Session-, History- und MCP-Konfiguration anderer Komponenten nicht lesen oder enumerieren.

**Detection/Verification:** Path classification, filesystem call analysis und boundary intent rules.

**Mindest-Evidence:** config/state path, operation und ownership.

**Aktuelles `skil`-Mapping:** `SKIL-BOUNDARY-AGENT-STATE`, `SKIL-BOUNDARY-MCP-CONFIG` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-11.06 — Peer Skill Isolation

**Normative Invariante:** Ein Skill darf andere installierte Skills, deren SKILL.md oder interne Ressourcen nicht ohne explizite Cross-Skill-Capability enumerieren oder lesen.

**Detection/Verification:** Peer-skill path detection, registry access analysis und contract verification.

**Mindest-Evidence:** peer skill path/identity, read/enumeration und authorization.

**Aktuelles `skil`-Mapping:** `SKIL-BOUNDARY-PEER-SKILL` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-11.07 — Container Control-Plane Isolation

**Normative Invariante:** Docker-/containerd-Sockets, Kubernetes Service Accounts und ähnliche Control-Plane-Interfaces dürfen einem Skill nicht implizit zugänglich sein.

**Detection/Verification:** Socket/path/env detection, mount analysis und runtime sandbox policy.

**Mindest-Evidence:** control-plane endpoint, accessible operation und inherited privilege.

**Aktuelles `skil`-Mapping:** `SKIL-BOUNDARY-CONTAINER` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-11.08 — Host Escape & Privilege-Escalation Prevention

**Normative Invariante:** Privileged Container, Host Namespaces, SYS_ADMIN, nsenter/unshare, cgroup escape und sudo/root-Eskalation müssen standardmäßig ausgeschlossen sein.

**Detection/Verification:** Container/IaC manifest analysis, shell AST und capability policy.

**Mindest-Evidence:** escape primitive, privilege delta und runtime enforcement.

**Aktuelles `skil`-Mapping:** `SKIL-BOUNDARY-CONTAINER-ESCAPE`, `SKIL-SH-002` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

# ASP-12 — Resource, Availability & Failure Containment

Begrenzt Kosten, Endlosschleifen, Ressourcenverbrauch und kaskadierende Fehlwirkungen.

**Primärer Crosswalk:** OWASP Agentic ASI02, ASI08, ASI10; OWASP LLM LLM06, LLM10; MITRE ATLAS AI Agent Tool Invocation.

## ASP-12.01 — Resource Budget Bound

**Normative Invariante:** CPU, Speicher, Tokens, API-Aufrufe, Geld und externe Ressourcen müssen pro Skill, Request oder Workflow begrenzt sein.

**Detection/Verification:** Static bound detection plus runtime budgets/meters.

**Mindest-Evidence:** resource type, configured bound und observed/requested use.

**Aktuelles `skil`-Mapping:** `SKIL-AGENCY-BOUNDS` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-12.02 — Output Bound

**Normative Invariante:** Generierte oder weitergeleitete Outputs müssen Größen-, Token- und Rate-Limits besitzen.

**Detection/Verification:** Config/pattern analysis und runtime output metering.

**Mindest-Evidence:** output channel, limit und attempted amount.

**Aktuelles `skil`-Mapping:** `SKIL-OUTPUT-LIMIT` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-12.03 — Rate & Quota Bound

**Normative Invariante:** Tool-, Netzwerk- und Provider-Aufrufe müssen Quoten und Ratenbegrenzungen respektieren.

**Detection/Verification:** Quota config linting, call counters und rate-policy enforcement.

**Mindest-Evidence:** operation, window, quota und observed rate.

**Aktuelles `skil`-Mapping:** `SKIL-AGENCY-BOUNDS` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-12.04 — Loop & Recursion Bound

**Normative Invariante:** Agentische Loops, Planner-Replanning, rekursive Skill-Aufrufe und Retry-Ketten benötigen maximale Tiefe oder eindeutige Terminierung.

**Detection/Verification:** Workflow graph cycle analysis, recursion counters und termination guards.

**Mindest-Evidence:** cycle/recursion edge, max depth und termination condition.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-12.05 — Cascading Failure Containment

**Normative Invariante:** Fehlerhafte Outputs oder Aktionen eines Skills dürfen nicht ungeprüft über abhängige Agenten, Pipelines oder Systeme eskalieren.

**Detection/Verification:** Dependency graph, trust gates, staged execution und blast-radius tests.

**Mindest-Evidence:** originating failure, propagation path und containment boundary.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-12.06 — Circuit Breaker & Kill-Switch Effectiveness

**Normative Invariante:** Bei Anomalien, Budgetüberschreitung oder Policy-Verstoß muss eine deterministische Unterbrechung weitere Aktionen stoppen.

**Detection/Verification:** Runtime circuit breaker tests, fail-closed policy und stop-signal conformance.

**Mindest-Evidence:** trigger event, breaker state und subsequent actions.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-12.07 — Retry & Backoff Safety

**Normative Invariante:** Retries dürfen weder unbegrenzte Last noch wiederholte irreversible Seiteneffekte erzeugen.

**Detection/Verification:** Retry config analysis, exponential backoff policy und side-effect classification.

**Mindest-Evidence:** retry policy, action idempotency und attempt count.

**Aktuelles `skil`-Mapping:** `SKIL-AGENCY-BOUNDS` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-12.08 — Idempotency & Duplicate-Action Safety

**Normative Invariante:** Wiederholte Planner- oder Tool-Aufrufe müssen bei nicht-idempotenten Aktionen durch deduplication keys, transaction boundaries oder confirmation geschützt sein.

**Detection/Verification:** Side-effect model, idempotency keys und transaction/audit traces.

**Mindest-Evidence:** action identity, repeated invocation und external effect.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

# ASP-13 — Human-Agent Trust & Safety

Schützt Nutzer vor Täuschung, Consent-Laundering, gefährlichen Operationszielen und unkritischem Vertrauen in Agentenausgaben.

**Primärer Crosswalk:** OWASP Agentic ASI01, ASI02, ASI09, ASI10; OWASP LLM LLM01, LLM06, LLM09; MITRE ATLAS AI Agent Clickbait, LLM Jailbreak.

## ASP-13.01 — Risk Disclosure Integrity

**Normative Invariante:** Sicherheitsrelevante Seiteneffekte und Risiken dürfen nicht absichtlich verschwiegen oder verharmlost werden.

**Detection/Verification:** Undisclosed-operation intent, behavior/description diff und high-impact action disclosure check.

**Mindest-Evidence:** risk/action, expected disclosure und actual disclosure.

**Aktuelles `skil`-Mapping:** `SKIL-INTENT-UNDISCLOSED-OPERATION` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-13.02 — Consent Specificity

**Normative Invariante:** Zustimmung zu einem Zweck oder einer Aktion darf nicht als Zustimmung zu zusätzlichen Datenzugriffen, Uploads, Retention oder Seiteneffekten interpretiert werden.

**Detection/Verification:** Consent scope model, action-to-consent binding und runtime policy.

**Mindest-Evidence:** consented scope versus effective action scope.

**Aktuelles `skil`-Mapping:** `SKIL-AGENCY-APPROVAL` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-13.03 — Deceptive Risk Framing Resistance

**Normative Invariante:** Ein Skill darf Berechtigungen oder riskante Aktionen nicht fälschlich als notwendig, harmlos, bereits genehmigt oder alternativlos darstellen.

**Detection/Verification:** Behavioral manipulation semantics und permission-necessity consistency.

**Mindest-Evidence:** claim, actual requirement/risk und mismatch.

**Aktuelles `skil`-Mapping:** `SKIL-INTENT-BEHAVIOR-MANIPULATION` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-13.04 — Confirmation UI/Message Integrity

**Normative Invariante:** Approval-Prompts müssen Aktion, Ziel, Datenklasse und irreversiblen Effekt korrekt darstellen und dürfen keine versteckten Zusatzaktionen bündeln.

**Detection/Verification:** Action preview generation und structured diff between requested and approved action.

**Mindest-Evidence:** displayed action versus executed action.

**Aktuelles `skil`-Mapping:** `SKIL-AGENCY-APPROVAL` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-13.05 — Physical-Harm Operational Safety

**Normative Invariante:** Skills dürfen keine operationalisierten Anweisungen erzeugen oder enthalten, deren Zweck die konkrete Verursachung physischer Schäden ist.

**Detection/Verification:** Action-anchored harmful intent rules mit defensivem Kontextfilter und semantic review.

**Mindest-Evidence:** harm objective, actionable steps und target/context.

**Aktuelles `skil`-Mapping:** `SKIL-ABUSE-PHYSICAL-HARM` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-13.06 — Malware & Phishing Objective Safety

**Normative Invariante:** Ein Skill darf Malware-Konstruktion, Credential-Harvesting-Impersonation oder vergleichbare bösartige Operationsziele nicht als legitimen Zweck verschleiern.

**Detection/Verification:** Abuse-intent classifiers, code/YARA evidence und behavior composition.

**Mindest-Evidence:** malicious objective, operational capability und target.

**Aktuelles `skil`-Mapping:** `SKIL-ABUSE-MALWARE`, `SKIL-ABUSE-PHISHING` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-13.07 — Destructive & Recovery-Inhibition Safety

**Normative Invariante:** Destruktive Aktionen, Backup-Löschung, Recovery-Hemmung und sabotageartige Operationen benötigen strikte Policy und dürfen nicht verdeckt ausgeführt werden.

**Detection/Verification:** Destructive-intent patterns, filesystem/cloud action classification und approvals.

**Mindest-Evidence:** destructive operation, recovery impact und authorization.

**Aktuelles `skil`-Mapping:** `SKIL-ABUSE-DESTRUCTION` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-13.08 — Security-Control Evasion Safety

**Normative Invariante:** Ein Skill darf Detection, Logging, EDR, Sandbox, Policy oder Sicherheitsprüfungen nicht mit dem Ziel der Umgehung deaktivieren oder sabotieren.

**Detection/Verification:** Evasion-intent patterns, control-target classification und runtime telemetry.

**Mindest-Evidence:** targeted control, evasion operation und intended effect.

**Aktuelles `skil`-Mapping:** `SKIL-ABUSE-EVASION` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

# ASP-14 — Auditability, Observability & Accountability

Macht Skill-Entscheidungen und Wirkungen sicherheitsrelevant nachvollziehbar, ohne private Chain-of-Thought zu verlangen.

**Primärer Crosswalk:** OWASP Agentic ASI03, ASI07, ASI08, ASI10; OWASP LLM LLM06, LLM09.

## ASP-14.01 — Action Attribution

**Normative Invariante:** Jede sicherheitsrelevante Aktion muss auf User/Caller, Agent, Skill-Version, Tool und Parameter zurückführbar sein.

**Detection/Verification:** Structured audit events, trace IDs und identity binding.

**Mindest-Evidence:** actor chain, artifact identity, tool call und result.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-14.02 — Authorization Decision Traceability

**Normative Invariante:** Für jede privilegierte Aktion muss nachvollziehbar sein, welche Policy, Capability und Approval sie erlaubt oder blockiert hat.

**Detection/Verification:** Policy decision logs, rule IDs und signed authorization context.

**Mindest-Evidence:** decision, evaluated policy, inputs und outcome.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-14.03 — Security Event Completeness

**Normative Invariante:** High-impact Reads/Writes, Secret-Zugriffe, Netzwerktransfers, Tool-Aufrufe, Persistenz und Policy-Verstöße müssen vollständig observierbar sein.

**Detection/Verification:** Event coverage matrix, runtime instrumentation und negative coverage tests.

**Mindest-Evidence:** expected event class versus emitted event.

**Aktuelles `skil`-Mapping:** `SKIL-TAINT-LOG` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-14.04 — Tamper-Evident Audit Records

**Normative Invariante:** Auditdaten müssen gegen nachträgliche Manipulation geschützt und mit Zeit, Identität und Artefaktversion korrelierbar sein.

**Detection/Verification:** Append-only/WORM log, signatures/hashes und trusted timestamps.

**Mindest-Evidence:** event hash chain/signature und storage policy.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-14.05 — Artifact & Version Attribution

**Normative Invariante:** Jedes Finding und Runtime-Event muss den exakten Digest der analysierten beziehungsweise ausgeführten Skill-Version referenzieren.

**Detection/Verification:** Digest capture at scan/install/runtime und event correlation.

**Mindest-Evidence:** artifact digest, version und source revision.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-14.06 — Evidence-Chain Reproducibility

**Normative Invariante:** Security Findings müssen aus Raw Evidence über Analyzer-Observation und Security-IR bis zur Policy-Entscheidung reproduzierbar sein.

**Detection/Verification:** Structured finding schema, deterministic analyzer metadata und evidence location.

**Mindest-Evidence:** raw span/node/path, analyzer, relation und decision.

**Aktuelles `skil`-Mapping:** `SKIL-* finding evidence model` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-14.07 — Failure & Denial Auditability

**Normative Invariante:** Abgebrochene, blockierte oder fehlgeschlagene Aktionen müssen mit Ursache und betroffener Policy protokolliert werden, ohne Secrets zu leaken.

**Detection/Verification:** Fail-closed audit hooks und sensitive-field redaction.

**Mindest-Evidence:** failure/deny event, rule und redacted context.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-14.08 — Coverage & Unknown-State Reporting

**Normative Invariante:** Scanner und Runtime dürfen fehlende Provider, nicht auflösbare Reflection, dynamische Downloads oder nicht beobachtete Pfade nicht als sicher deklarieren.

**Detection/Verification:** Explicit coverage states, analyzer capability inventory und unresolved-edge reporting.

**Mindest-Evidence:** verified/partial/runtime-dependent/semantic-only/not-observable state.

**Aktuelles `skil`-Mapping:** `Provider coverage reporting` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

# ASP-15 — Dependency, Package & Container Supply-Chain Security

Behandelt klassische Software-Supply-Chain-Risiken innerhalb von Skills als eigenständige Properties statt als Analyzer-Namen.

**Primärer Crosswalk:** OWASP Agentic ASI04, ASI05; OWASP LLM LLM03; MITRE ATLAS AI Supply Chain Rug Pull, AI Supply Chain Reputation Inflation.

## ASP-15.01 — Dependency Pinning

**Normative Invariante:** Abhängigkeiten müssen auf überprüfbare Versionen, Digests oder Lockfile-Auflösungen gebunden sein.

**Detection/Verification:** Manifest/lockfile parsing und version-constraint semantics.

**Mindest-Evidence:** dependency name, requested constraint und resolved version/digest.

**Aktuelles `skil`-Mapping:** `SKIL-DEP-001` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-15.02 — Known Vulnerability Hygiene

**Normative Invariante:** Aufgelöste Abhängigkeiten dürfen keine nicht akzeptierten bekannten Vulnerabilities enthalten.

**Detection/Verification:** SBOM/dependency inventory plus OSV/CVE lookup und policy threshold.

**Mindest-Evidence:** package ecosystem/name/version, advisory und fix/exception.

**Aktuelles `skil`-Mapping:** `SKIL-DEP-VULN` — **PROVIDER_BACKED**.

**Assurance:** Provider-Abwesenheit muss als `PROVIDER_UNAVAILABLE` beziehungsweise `PARTIALLY_VERIFIED` erscheinen, nicht als sicher.

## ASP-15.03 — Package Identity & Typosquatting Resistance

**Normative Invariante:** Package-Namen müssen gegen bekannte Namespaces, Homoglyphen und edit-distance-basierte Verwechslungen geprüft werden.

**Detection/Verification:** Ecosystem-aware canonical names, edit distance, confusables und registry metadata.

**Mindest-Evidence:** requested package, nearest canonical identity und distance/evidence.

**Aktuelles `skil`-Mapping:** `SKIL-DEP-002`, `SKIL-UNI-002` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

## ASP-15.04 — Dependency Maintenance & Reputation

**Normative Invariante:** Abandoned, übernommen oder reputationsschwache Dependencies müssen als erhöhtes Supply-Chain-Risiko bewertet werden.

**Detection/Verification:** Maintainer/release recency evidence, curated reputation und ownership change signals.

**Mindest-Evidence:** package, maintenance evidence und risk rationale.

**Aktuelles `skil`-Mapping:** `SKIL-DEP-ABANDONED` — **PROVIDER_BACKED**.

**Assurance:** Provider-Abwesenheit muss als `PROVIDER_UNAVAILABLE` beziehungsweise `PARTIALLY_VERIFIED` erscheinen, nicht als sicher.

## ASP-15.05 — Dependency Namespace/Confusion Resistance

**Normative Invariante:** Interne und öffentliche Package-Namespaces dürfen keine ungewollte Auflösung auf attacker-controlled Pakete ermöglichen.

**Detection/Verification:** Registry/source priority analysis, namespace ownership und package source pinning.

**Mindest-Evidence:** package name, configured registries und actual resolution source.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-15.06 — Lockfile Integrity

**Normative Invariante:** Lockfiles und resolved dependency graphs müssen Teil der geprüften Artefaktintegrität sein und dürfen nicht zur Laufzeit stillschweigend neu aufgelöst werden.

**Detection/Verification:** Lockfile presence/digest, reproducible resolution checks und artifact signature coverage.

**Mindest-Evidence:** lock digest, resolved graph und execution graph.

**Aktuelles `skil`-Mapping:** kein dedizierter Control — **NEW**.

**Assurance:** Vor einer Implementierung muss geklärt werden, welche deterministische Evidence verfügbar ist und welcher Rest Runtime-/Semantic-Assurance bleibt.

## ASP-15.07 — Remote Script & Runtime Dependency Integrity

**Normative Invariante:** Zur Laufzeit geladene Skripte, Plugins oder Assets müssen pinbar, verifizierbar und innerhalb der erlaubten Artifact Closure liegen.

**Detection/Verification:** Remote fetch AST/shell analysis, URL/digest pinning und sandbox download policy.

**Mindest-Evidence:** remote URI, expected digest/version und execution sink.

**Aktuelles `skil`-Mapping:** `SKIL-SH-001` — **PARTIAL**.

**Assurance:** Vorhandene Controls stützen Teilaspekte; vollständige Konformität benötigt zusätzliche Lifecycle-, Identity-, Dataflow- oder Runtime-Evidence.

## ASP-15.08 — Container Image Trust

**Normative Invariante:** Container Images müssen vertrauenswürdige Registries, immutable Digests/zulässige Tags und aktivierte Content-Trust-/Verification-Mechanismen verwenden.

**Detection/Verification:** Image reference parsing, tag/digest policy und trust flag analysis.

**Mindest-Evidence:** image identity, registry, tag/digest und trust setting.

**Aktuelles `skil`-Mapping:** `SKIL-CONTAINER-TRUST`, `SKIL-BOUNDARY-MUTABLE-IMAGE` — **IMPLEMENTED**.

**Assurance:** Der Kern ist nativ prüfbar; vollständige Assurance kann für dynamisches Verhalten weiterhin Runtime-Evidence erfordern.

# 8. Was ausdrücklich keine Security Property ist

| Begriff | Korrekte Rolle |
|---|---|
| Python AST / AST1–AST9 | Syntax-/Semantik-Analysemechanismus |
| JavaScript/TypeScript AST | Analysemechanismus |
| Bash/Shell Analysis | Analysemechanismus |
| Taint Tracking | Dataflow-/Information-Flow-Mechanismus |
| YARA | Signatur-/Pattern-Engine |
| OSV/CVE | Vulnerability-Evidence-Quelle |
| Unicode/Bidi Scanner | Evidence-Mechanismus |
| LLM Semantic Analysis | probabilistischer Analyzer |
| Risk Score | Aggregations-/Priorisierungsmechanismus |

Beispiel: **ASP-06.07 Information-Flow Integrity** ist die Property; **Taint Tracking** ist ein Mechanismus, der Verletzungen belegen kann.

# 9. Finding- und Assurance-Modell

Ein konformes System SOLLTE Security-Entscheidungen strukturiert ausgeben:

```yaml
property_id: ASP-06.07
state: VIOLATED
confidence: high
coverage: VERIFIED
artifact_digest: sha256:...
location:
  file: scripts/run.py
  line: 42
evidence:
  source: os.environ["TOKEN"]
  propagation:
    - token
    - payload
  sink: requests.post
detector:
  class: taint
  implementation: builtin
policy:
  decision: deny
references:
  - OWASP ASI02
```

## 9.1 Evaluationsmetriken

**Deterministische Controls**
- Precision, Recall/TPR, FPR/FNR
- negative-fixture cleanliness
- Parser-/Resolution-Failure-Rate
- Path/Branch Coverage

**Semantische Controls**
- kalibrierte Confidence
- inter-run/inter-model agreement
- adversarial paraphrase robustness
- abstention/unknown rate
- Kosten/Latenz

**Runtime Controls**
- Policy Violation Detection Rate
- Taint/Information-Flow Accuracy
- Blocked Malicious Action Rate
- False Blocking Rate
- Tool-/OS-Boundary Coverage

# 10. Lifecycle-Modell

```text
Authoring
  ↓
Admission
  ↓
Storage / Registry
  ↓
Discovery / Retrieval
  ↓
Planner Selection
  ↓
Installation
  ↓
Execution / Composition
  ↓
State / Persistence
  ↓
Evolution / Update
  ↓
Revocation / Removal
```

Eine erfolgreiche Admission-Prüfung erzeugt **keinen permanenten Trust**. Jede neue Version und jede Änderung an Permissions, Tools, Dependencies, Metadaten oder Artifact Closure muss erneut bewertet werden.

# 11. Zielarchitektur für `skil`

```text
Artifact Intake
      ↓
Raw + Structural Normalization
      ↓
Evidence Producers
Pattern | AST | CFG | Taint | Dependency | MCP
Boundary | Identity | Provenance | YARA | Runtime | Semantic
      ↓
Security IR
actor/action/source/sink/scope/identity/trust/version/guard
      ↓
Property Evaluator
ASP-xx.yy predicates
      ↓
Policy + Assurance Decision
VERIFIED / VIOLATED / UNKNOWN / ...
```

**Rule IDs sind nicht die Taxonomie.** Rules produzieren Evidence; Properties definieren Invarianten; Policies entscheiden.

# 12. Priorisierte Erweiterungen für `skil`

1. **Lifecycle/Registry Security:** Signaturen, Publisher Identity, Provenance, Rollback, Update-Revalidation.
2. **Retrieval/Planner Security:** Keyword Stuffing, Semantic Camouflage, Sybil/Clone Detection, Fake Reputation.
3. **Identity/Delegation:** Token Audience, Non-Transferability, Delegation Monotonicity, Confused Deputy.
4. **Inter-Agent Security:** Message Integrity, Trust Propagation, Delegation Traceability.
5. **Runtime Assurance:** Detonation/Sandboxing, OS-boundary Evidence, Runtime Artifact Measurement.
6. **Availability:** Loop Bounds, Cascading Failure Containment, Circuit Breaker.
7. **Auditability:** Digest-attributed Findings und explizites Unknown-State Reporting.

# 13. Migration des bisherigen 63-Property-Katalogs


| Bisheriger Begriff | ASPS-Ziel | Einordnung |
|---|---|---|
| Instruction Override | `ASP-01.01` | PROPERTY |
| Role/Context Manipulation | `ASP-01.02` | PROPERTY |
| Anti-Refusal | `ASP-01.03` | PROPERTY |
| Warning Suppression | `ASP-01.04` | PROPERTY |
| Guardrail Nullification | `ASP-01.05` | PROPERTY |
| Hidden/Invisible Instructions | `ASP-01.06` | PROPERTY |
| Behavioral Steering / Manipulation | `ASP-01.07` | PROPERTY |
| Generic Physical Harm | `ASP-13.05` | PROPERTY |
| HTTP/Data Exfiltration | `ASP-03.05` | PROPERTY |
| Env/Secret Harvesting | `ASP-03.01` | PROPERTY |
| Filesystem Reconnaissance | `ASP-11.05/ASP-11.06` | PROPERTY_SPLIT |
| Conversation/Context Exfiltration | `ASP-03.03` | PROPERTY |
| Cloud Storage Exfiltration | `ASP-03.06` | PROPERTY |
| Excessive Permissions | `ASP-04.01` | PROPERTY |
| sudo/root escalation | `ASP-11.08` | PROPERTY |
| Credential-file access | `ASP-03.02` | PROPERTY |
| Docker Socket | `ASP-11.07` | PROPERTY |
| Container Escape / privileged workload | `ASP-11.08` | PROPERTY |
| Unrestricted Tool Access | `ASP-05.01` | PROPERTY |
| Approval Bypass | `ASP-04.04` | PROPERTY |
| Scope Creep | `ASP-01.08` | PROPERTY |
| Missing Resource Bounds | `ASP-12.01` | PROPERTY |
| Output → Execution | `ASP-06.05` | PROPERTY |
| Cross-context Output | `ASP-06.06` | PROPERTY |
| Output Limits | `ASP-12.02` | PROPERTY |
| Direct Prompt Leakage | `ASP-03.04` | SUBPROPERTY |
| Indirect Prompt Leakage | `ASP-03.04` | SUBPROPERTY |
| Prompt → external/tool exfil | `ASP-03.04/ASP-03.05` | PROPERTY_COMPOSITION |
| Memory Poisoning | `ASP-07.01` | PROPERTY |
| Context Stuffing | `ASP-07.02` | PROPERTY |
| Memory/State Manipulation | `ASP-07.03` | PROPERTY |
| Self Modification | `ASP-07.04` | PROPERTY |
| Persistence | `ASP-07.05` | PROPERTY |
| Trigger Abuse | `ASP-02.03` | PROPERTY |
| Trigger Shadowing | `ASP-02.04` | PROPERTY |
| Tool Parameter Abuse | `ASP-05.02` | PROPERTY |
| Tool Chaining | `ASP-05.03` | PROPERTY |
| Unsafe Defaults | `ASP-05.05` | PROPERTY |
| Python AST AST1–AST9 | `ASP-06.01/ASP-06.02/ASP-06.04` | MECHANISM_FAMILY |
| JS/TS Process Execution | `ASP-06.02` | PROPERTY |
| Bash/Shell Analysis | `ASP-06.03` | MECHANISM |
| Taint Tracking | `ASP-06.07` | MECHANISM |
| Unicode/Bidi/Confusables | `ASP-01.06/ASP-15.03` | MECHANISM |
| Obfuscation | `ASP-06.08` | PROPERTY |
| YARA/Malware | `ASP-06.08` | MECHANISM |
| Dependency Pinning | `ASP-15.01` | PROPERTY |
| OSV/CVE | `ASP-15.02` | EVIDENCE_SOURCE |
| Typosquatting | `ASP-15.03` | PROPERTY |
| Abandoned Packages | `ASP-15.04` | PROPERTY |
| Container Trust | `ASP-15.08` | PROPERTY |
| MCP Wildcards | `ASP-10.01` | PROPERTY |
| MCP Metadata Poisoning | `ASP-10.02` | PROPERTY |
| MCP Parameter Injection | `ASP-10.03` | PROPERTY |
| Description/Behavior mismatch | `ASP-02.02/ASP-10.05` | PROPERTY |
| MCP Rug Pull / mutable identity | `ASP-10.04/ASP-09.06` | PROPERTY_COMPOSITION |
| Underdeclared Capability | `ASP-04.02` | PROPERTY |
| Overdeclared Capability | `ASP-04.03` | PROPERTY |
| Agent Config Snooping | `ASP-11.05` | PROPERTY |
| MCP Config Snooping | `ASP-11.05` | PROPERTY |
| Peer Skill Enumeration | `ASP-11.06` | PROPERTY |
| Cloud Metadata SSRF | `ASP-11.02` | PROPERTY |
| Internal/Loopback SSRF | `ASP-11.03` | PROPERTY |
| Dynamic-target SSRF | `ASP-11.04` | PROPERTY |

## 13.1 Konsequenz

Mehrere bisherige Begriffe bleiben valide Properties, werden aber in eine hierarchische Domäne eingeordnet. Andere Begriffe werden bewusst umklassifiziert:

- `Taint Tracking` → Mechanismus für `ASP-06.07`.
- `Python AST AST1–AST9` → Mechanismus-/Pattern-Familie für mehrere Code-Execution-Properties.
- `Bash/Shell Analysis` → Mechanismus für `ASP-06.03`.
- `YARA` → Malware-/Pattern-Engine für `ASP-06.08`.
- `OSV/CVE` → externe Vulnerability-Evidence für `ASP-15.02`.

# 14. Wissenschaftliche Einordnung

ASPS synthetisiert verschiedene Perspektiven:

- **OWASP Agentic Top 10 2026** priorisiert systemische Risikoklassen agentischer Anwendungen.
- **OWASP LLM Top 10 2025** liefert relevante Modell-/Applikationsrisiken wie Prompt Injection, Sensitive Information Disclosure, Supply Chain, Improper Output Handling, Excessive Agency und Unbounded Consumption.
- **MITRE ATLAS** beschreibt Angreifertechniken und Operationspfade.
- **MCP Security Best Practices** spezifiziert konkrete Protokoll- und OAuth-Risiken wie Confused Deputy, Token Passthrough, SSRF, State Handle Hijacking und Scope Minimization.
- **NIST AI 600-1** liefert Risk-Management-/Trustworthiness-Rahmen.
- **SLSA/Sigstore** liefern Provenance-, Signatur- und Artifact-Integrity-Bausteine.
- **Scanner-Kataloge** operationalisieren Skill-Risiken als Scanner-Patterns; das ist ein Scanner-Katalog, kein Standard.
- **Skill-Security-Forschung 2026** erweitert statisches Scanning um Lifecycle, Retrieval, Planner, Evolution und Runtime-Verhalten.

# 15. Referenzen


1. **OWASP Top 10 for Agentic Applications 2026** — OWASP GenAI Security Project. https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
2. **OWASP Top 10 for LLM Applications 2025** — OWASP GenAI Security Project. https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
3. **MITRE ATLAS** — MITRE. https://atlas.mitre.org/
4. **MCP Security Best Practices — 2026-07-28** — Model Context Protocol. https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices
5. **NIST AI 600-1 — Generative AI Profile** — NIST. https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
6. **SLSA Specification v1.2** — OpenSSF/SLSA. https://slsa.dev/spec/v1.2/
7. **Sigstore Documentation** — OpenSSF/Sigstore. https://docs.sigstore.dev/
8. **NVIDIA-Verified Agent Skills** — NVIDIA. https://docs.nvidia.com/skills
9. **Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale** — Liu et al. (2026). https://arxiv.org/abs/2601.10338
10. **Malicious Agent Skills in the Wild: A Large-Scale Security Empirical Study** — Liu et al. (2026). https://arxiv.org/abs/2602.06547
11. **Towards Secure Agent Skills: Architecture, Threat Taxonomy, and Security Analysis** — Li et al. (2026). https://arxiv.org/abs/2604.02837
12. **Runtime Skill Audit: Targeted Runtime Probing for Agent Skill Security** — Lan & Xiao (2026). https://arxiv.org/abs/2606.11671
13. **Detecting Malicious Agent Skills in the Wild using Attention** — Etteib et al. (2026). https://arxiv.org/abs/2606.23416
14. **Cloak and Detonate: Scanner Evasion and Dynamic Detection of Agent Skill Malware** — Ji et al. (2026). https://arxiv.org/abs/2607.02357
15. **Agent Skill Security: Threat Models, Attacks, Defenses, and Evaluation** — Badhe & Tiwari (2026). https://arxiv.org/abs/2607.13987
16. **Skillware: A Software Ontology and Engineering Lifecycle for Persistent Behavioral Artifacts** — Fan & Lan (2026). https://arxiv.org/abs/2607.18970
17. **Agent Skills open specification** — Agent Skills. https://agentskills.io/
18. **skil security control matrix** — domehahn/skil. https://github.com/domehahn/skil/blob/main/docs/security-control-matrix.md
19. **skil external control crosswalk** — domehahn/skil. https://github.com/domehahn/skil/blob/main/docs/external-control-crosswalk.md