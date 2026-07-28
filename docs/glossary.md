# Glossary

- **Skill:** instructions and optional resources that extend an agent.
- **Skill package:** the bounded artifact containing a skill and its files.
- **Skill contract:** a versioned declaration of identity and allowed behavior.
- **Capability:** an operation class a skill may need.
- **Permission:** a constrained grant for a capability.
- **Finding:** evidence-backed analyzer observation, not proof of exploitability.
- **Rule:** stable detection or decision logic with rationale and remediation.
- **Analyzer:** one implementation of an analysis technique.
- **Scanner:** orchestration of analyzers over an untrusted artifact.
- **Evaluation:** controlled observation of executed agent behavior.
- **Behavioral test:** a task and non-exact assertions about expected behavior.
- **Adversarial test:** a behavioral test containing a security attack.
- **Evidence:** producer-stamped output bound to an exact artifact digest.
- **Attestation:** a portable statement summarizing evidence for a subject.
- **Provenance:** how, where, when, and by whom an artifact was built.
- **Policy:** environment-specific acceptance requirements.
- **Verification:** comparison of observed behavior with the declared contract.
- **Validation:** structural and semantic well-formedness checking.
- **Risk:** transparent estimate derived from severity, confidence, capability
  mismatch, side effects, exploitability proxies, and coverage.
- **Assurance:** the verification activities completed; not a claim of safety.
- **Runtime enforcement:** actual prevention of prohibited operations during
  execution, outside the scanner.
