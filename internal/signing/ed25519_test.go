package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

func TestAttestationSignatureRejectsTamperingAndUntrustedKeys(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := KeyID(publicKey)
	attestation := skil.Attestation{
		Version: 1, Subject: skil.Subject{Name: "skill", SHA256: "abc"},
		Timestamp: time.Now().UTC(),
	}
	if err := SignAttestation(&attestation, privateKey, keyID); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]string{keyID: base64PublicKey(publicKey)}
	if err := VerifyAttestation(attestation, trusted); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttestation(attestation, map[string]string{}); err == nil {
		t.Fatal("expected untrusted key rejection")
	}
	attestation.Subject.SHA256 = "def"
	if err := VerifyAttestation(attestation, trusted); err == nil {
		t.Fatal("expected tampering rejection")
	}
}

func base64PublicKey(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key)
}

// TestAttestationSignatureVerifiableWithoutSkilStructs proves the property
// P1 #8 in the cross-repo hardening plan depends on: a verifier outside
// this module (skpm, SkillForge) can check a skil-produced attestation
// signature using only the wire JSON bytes plus the canonicalization
// algorithm documented on CanonicalJSON — without importing skil's Go
// types at all. It stands in for such a verifier using
// map[string]json.RawMessage, which has no knowledge of skil.Attestation's
// field order, count, or types beyond "it's a JSON object with a
// signature key".
func TestAttestationSignatureVerifiableWithoutSkilStructs(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := KeyID(publicKey)
	attestation := skil.Attestation{
		Version:   1,
		Subject:   skil.Subject{Name: "skill", SHA256: "abc"},
		Producer:  skil.Producer{Name: "skil", Version: "0.1.0"},
		Result:    skil.AttestResult{Status: skil.Status("pass"), RiskScore: 3},
		Analysis:  []string{"lint", "eval"},
		Timestamp: time.Now().UTC(),
		Evidence: []skil.Evidence{{
			Type: "lint", Producer: "skil", ProducerVer: "0.1.0",
			SubjectDigest: "abc", Timestamp: time.Now().UTC(),
			Result: skil.EvidenceResult{Status: skil.Status("pass"), MaximumSeverity: skil.Severity("none"), Findings: 0},
		}},
	}
	if err := SignAttestation(&attestation, privateKey, keyID); err != nil {
		t.Fatal(err)
	}

	wire, err := json.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}

	// A foreign verifier: decode generically, pull out and remove
	// "signature", canonicalize what's left, and verify — none of this
	// touches skil.Attestation.
	var envelope map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(wire))
	dec.UseNumber()
	if err := dec.Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	sigRaw, ok := envelope["signature"]
	if !ok {
		t.Fatal("expected a signature field in the wire JSON")
	}
	var sig skil.Signature
	if err := json.Unmarshal(sigRaw, &sig); err != nil {
		t.Fatal(err)
	}
	delete(envelope, "signature")

	payload, err := CanonicalJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]string{keyID: base64PublicKey(publicKey)}
	if err := verify(payload, sig, trusted); err != nil {
		t.Fatalf("independent verification failed: %v", err)
	}

	// Tampering with any field the foreign verifier can see must still be
	// caught, exactly as it would be for skil's own verifier.
	tamperedSubject, _ := json.Marshal(map[string]any{"name": "skill", "sha256": "def"})
	envelope["subject"] = tamperedSubject
	tamperedPayload, err := CanonicalJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(tamperedPayload, sig, trusted); err == nil {
		t.Fatal("expected independent verification to reject a tampered subject")
	}
}

func TestDSSEProvenanceBindsSubjectAndRejectsTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := CreateProvenance("skill.tgz", "abc", "https://example.test/repo", "deadbeef", "builder", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := SignProvenance(&provenance, privateKey, ""); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]string{KeyID(publicKey): base64PublicKey(publicKey)}
	if err := VerifyProvenance(provenance, trusted); err != nil {
		t.Fatal(err)
	}
	statement, err := ParseProvenance(provenance)
	if err != nil || statement.Type != "https://in-toto.io/Statement/v1" ||
		statement.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Fatalf("invalid statement: %#v %v", statement, err)
	}
	provenance.Payload += "A"
	if err := VerifyProvenance(provenance, trusted); err == nil {
		t.Fatal("tampered DSSE payload must be rejected")
	}
}
