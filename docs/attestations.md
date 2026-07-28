# Evidence and attestations

Evidence records its type, producer/version, timestamp, payload digest, and
subject artifact digest. Packaged artifacts use the raw archive SHA-256;
directories use their reproducible content-manifest SHA-256. An attestation
summarizes completed analyses and result status for one exact subject.

`skil key generate` creates a PKCS#8 Ed25519 private key without overwriting an
existing file and prints the public key plus its fingerprint. `skil attest
--signing-key` signs the canonical attestation envelope. A policy accepts that
signature only when `trusted_signers` maps its key ID to the expected base64
public key; non-empty signature metadata is not sufficient.

External SARIF must declare `properties.skil.subject_digest`. `skil evidence
sign` embeds the SARIF payload and creates a signed envelope binding scanner
identity, artifact digest, timestamp, normalized verdict, coverage, finding
count, and payload digest. Policy counts a passing external scanner only after
payload hashing, verdict evaluation, signature verification, age checks, and
scanner-specific key binding all succeed.
