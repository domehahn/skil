# ADR 0002: One deterministic finding model

Status: accepted. Every analyzer returns the same typed finding with stable rule
ID, category, severity, confidence, location, evidence, remediation, references,
and SHA-256 fingerprint. Baselines mark findings suppressed but retain them.
