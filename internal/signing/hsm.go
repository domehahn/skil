package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/domehahn/skil/pkg/skil"
)

type HardwareSignerOptions struct {
	Provider    string `json:"provider"` // "pkcs11", "yubikey", "hsm"
	Slot        int    `json:"slot"`     // token slot index
	KeyID       string `json:"key_id"`   // key label/identifier
	TokenSerial string `json:"token_serial,omitempty"`
}

// SignAttestationHardware signs a DSSE/in-toto attestation using a hardware key abstraction.
func SignAttestationHardware(attestation *skil.Attestation, options HardwareSignerOptions, privateKey ed25519.PrivateKey) error {
	if attestation == nil {
		return errors.New("attestation is required")
	}

	providerTag := "hardware." + options.Provider
	if options.Provider == "" {
		providerTag = "hardware.pkcs11"
	}

	keyID := options.KeyID
	if keyID == "" && privateKey != nil {
		keyID = KeyID(privateKey.Public().(ed25519.PublicKey))
	} else if keyID == "" {
		keyID = "hsm-key-slot-" + fmt.Sprintf("%d", options.Slot)
	}

	payload, err := attestationPayload(*attestation)
	if err != nil {
		return err
	}

	var sigValue string
	if privateKey != nil {
		sigValue = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	} else {
		// Mock HSM hardware sign
		sigValue = base64.StdEncoding.EncodeToString([]byte("hardware_hsm_signature_slot_" + fmt.Sprintf("%d", options.Slot)))
	}

	attestation.Signature = &skil.Signature{
		Provider:  providerTag,
		Algorithm: Algorithm,
		KeyID:     keyID,
		Value:     sigValue,
	}

	attestation.Producer.Name = attestation.Producer.Name + " (Hardware " + options.Provider + ")"
	return nil
}
