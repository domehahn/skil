package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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
