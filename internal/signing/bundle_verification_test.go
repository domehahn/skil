package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestVerifyDSSEBundleDistinguishesRecognizedFromVerified(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := KeyID(pub)
	trusted := map[string]string{keyID: base64.StdEncoding.EncodeToString(pub)}

	prov, err := CreateProvenance("skill-a", "abcd1234", "https://github.com/example/repo", "deadbeef", "https://github.com/actions/runner", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// 1. Unsigned DSSE wrapper is Recognized and Inspected, but NOT CryptographicallyVerified or TrustPolicyAccepted.
	unsignedBytes, _ := json.Marshal(prov)
	rep, err := VerifyDSSEBundle(unsignedBytes, BundleTrustPolicy{
		ExpectedSubjectSHA256: "abcd1234",
		TrustedKeys:           trusted,
	})
	if err == nil {
		t.Fatal("unsigned DSSE bundle must not be accepted as verified")
	}
	if !rep.Recognized || !rep.Inspected || rep.CryptographicallyVerified || rep.TrustPolicyAccepted {
		t.Fatalf("unexpected stage flags for unsigned bundle: %+v", rep)
	}

	// 2. Signed DSSE bundle with mismatched artifact subject fails at TrustPolicyAccepted.
	if err := SignProvenance(&prov, priv, keyID); err != nil {
		t.Fatal(err)
	}
	signedBytes, _ := json.Marshal(prov)
	repMismatch, err := VerifyDSSEBundle(signedBytes, BundleTrustPolicy{
		ExpectedSubjectSHA256: "different_digest",
		TrustedKeys:           trusted,
	})
	if err == nil {
		t.Fatal("signed bundle with mismatched subject digest must fail trust policy")
	}
	if !repMismatch.CryptographicallyVerified || !repMismatch.SignerValidated || repMismatch.TrustPolicyAccepted {
		t.Fatalf("expected crypto+signer valid but trust policy rejected, got %+v", repMismatch)
	}

	// 3. Signed DSSE bundle with matching subject and builder succeeds all 5 stages.
	repOK, err := VerifyDSSEBundle(signedBytes, BundleTrustPolicy{
		ExpectedSubjectSHA256: "abcd1234",
		TrustedKeys:           trusted,
		AllowedBuilders:       []string{"https://github.com/actions/runner"},
	})
	if err != nil || !repOK.TrustPolicyAccepted || repOK.Stage != BundleTrustPolicyAccepted {
		t.Fatalf("expected full trust policy acceptance, got %+v err=%v", repOK, err)
	}
}
