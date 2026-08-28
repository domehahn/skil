package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestSignAttestationHardwareBindsHardwareProvider(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	att := skil.Attestation{
		Subject:  skil.Subject{Name: "test-skill", SHA256: "abc"},
		Producer: skil.Producer{Name: "skil", Version: "1.0.0"},
	}

	opts := HardwareSignerOptions{
		Provider: "yubikey",
		Slot:     0,
		KeyID:    KeyID(pub),
	}

	if err := SignAttestationHardware(&att, opts, priv); err != nil {
		t.Fatalf("SignAttestationHardware failed: %v", err)
	}

	if att.Signature == nil {
		t.Fatalf("expected signature on attestation")
	}

	if att.Signature.Provider != "hardware.yubikey" {
		t.Fatalf("unexpected provider tag: %s", att.Signature.Provider)
	}

	if !strings.Contains(att.Producer.Name, "Hardware yubikey") {
		t.Fatalf("expected hardware producer annotation, got %s", att.Producer.Name)
	}
}
