package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

const (
	Provider  = "builtin.ed25519"
	Algorithm = "Ed25519"
)

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("signing key must be a PEM encoded PKCS#8 Ed25519 private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 signing key: %w", err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not Ed25519")
	}
	return privateKey, nil
}

func GeneratePrivateKey(path string) (string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate Ed25519 key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("encode private key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("create private key without overwriting: %w", err)
	}
	writeErr := pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	closeErr := file.Close()
	if writeErr != nil {
		return "", "", fmt.Errorf("write private key: %w", writeErr)
	}
	if closeErr != nil {
		return "", "", fmt.Errorf("close private key: %w", closeErr)
	}
	return KeyID(publicKey), base64.StdEncoding.EncodeToString(publicKey), nil
}

func PublicKeyBase64(privateKey ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
}

func KeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func SignAttestation(attestation *skil.Attestation, privateKey ed25519.PrivateKey, keyID string) error {
	if attestation == nil {
		return errors.New("attestation is required")
	}
	if keyID == "" {
		keyID = KeyID(privateKey.Public().(ed25519.PublicKey))
	}
	payload, err := attestationPayload(*attestation)
	if err != nil {
		return err
	}
	attestation.Signature = &skil.Signature{
		Provider: Provider, Algorithm: Algorithm, KeyID: keyID,
		Value: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	return nil
}

func VerifyAttestation(attestation skil.Attestation, trustedKeys map[string]string) error {
	if attestation.Signature == nil {
		return errors.New("attestation signature is missing")
	}
	payload, err := attestationPayload(attestation)
	if err != nil {
		return err
	}
	return verify(payload, *attestation.Signature, trustedKeys)
}

func SignProvenance(provenance *skil.Provenance, privateKey ed25519.PrivateKey, keyID string) error {
	if provenance == nil {
		return errors.New("provenance is required")
	}
	if keyID == "" {
		keyID = KeyID(privateKey.Public().(ed25519.PublicKey))
	}
	payload, err := base64.StdEncoding.DecodeString(provenance.Payload)
	if err != nil {
		return errors.New("provenance payload is not valid base64")
	}
	pae := DSSEPAE(provenance.PayloadType, payload)
	provenance.Signatures = []skil.DSSESignature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, pae))}}
	return nil
}

func VerifyProvenance(provenance skil.Provenance, trustedKeys map[string]string) error {
	if len(provenance.Signatures) == 0 {
		return errors.New("provenance signature is missing")
	}
	payload, err := base64.StdEncoding.DecodeString(provenance.Payload)
	if err != nil {
		return errors.New("provenance payload is not valid base64")
	}
	pae := DSSEPAE(provenance.PayloadType, payload)
	for _, item := range provenance.Signatures {
		if err := verify(pae, skil.Signature{Provider: Provider, Algorithm: Algorithm, KeyID: item.KeyID, Value: item.Sig}, trustedKeys); err == nil {
			return nil
		}
	}
	return errors.New("no trusted DSSE signature verified")
}

func CreateProvenance(name, packageDigest, repository, commit, builder string, now time.Time) (skil.Provenance, error) {
	statement := skil.InTotoStatement{
		Type:          "https://in-toto.io/Statement/v1",
		Subject:       []skil.InTotoSubject{{Name: name, Digest: map[string]string{"sha256": packageDigest}}},
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: skil.SLSAPredicate{
			BuildDefinition: skil.SLSABuildDefinition{
				BuildType:            "https://github.com/domehahn/skil/build/v1",
				ExternalParameters:   map[string]string{"source_repository": repository, "source_commit": commit},
				ResolvedDependencies: []skil.SLSAResource{{URI: repository, Digest: map[string]string{"gitCommit": commit}}},
			},
			RunDetails: skil.SLSARunDetails{Builder: skil.SLSABuilder{ID: builder}, Metadata: skil.SLSAMetadata{StartedOn: now, FinishedOn: now}},
		},
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		return skil.Provenance{}, err
	}
	return skil.Provenance{PayloadType: "application/vnd.in-toto+json", Payload: base64.StdEncoding.EncodeToString(payload), Signatures: []skil.DSSESignature{}}, nil
}

func ParseProvenance(provenance skil.Provenance) (skil.InTotoStatement, error) {
	var statement skil.InTotoStatement
	if provenance.PayloadType != "application/vnd.in-toto+json" {
		return statement, fmt.Errorf("unsupported DSSE payload type %q", provenance.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(provenance.Payload)
	if err != nil {
		return statement, errors.New("provenance payload is not valid base64")
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return statement, fmt.Errorf("parse in-toto statement: %w", err)
	}
	return statement, nil
}

func DSSEPAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func SignPackageStatement(statement *skil.PackageStatement, privateKey ed25519.PrivateKey, keyID string) error {
	if statement == nil {
		return errors.New("package statement is required")
	}
	if keyID == "" {
		keyID = KeyID(privateKey.Public().(ed25519.PublicKey))
	}
	payload, err := packagePayload(*statement)
	if err != nil {
		return err
	}
	statement.Signature = &skil.Signature{Provider: Provider, Algorithm: Algorithm, KeyID: keyID,
		Value: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))}
	return nil
}

func VerifyPackageStatement(statement skil.PackageStatement, trustedKeys map[string]string) error {
	if statement.Signature == nil {
		return errors.New("package signature is missing")
	}
	payload, err := packagePayload(statement)
	if err != nil {
		return err
	}
	return verify(payload, *statement.Signature, trustedKeys)
}

func SignEvidenceBundle(bundle *skil.EvidenceBundle, privateKey ed25519.PrivateKey, keyID string) error {
	if bundle == nil {
		return errors.New("evidence bundle is required")
	}
	if keyID == "" {
		keyID = KeyID(privateKey.Public().(ed25519.PublicKey))
	}
	payload, err := evidencePayload(*bundle)
	if err != nil {
		return err
	}
	bundle.Signature = &skil.Signature{
		Provider: Provider, Algorithm: Algorithm, KeyID: keyID,
		Value: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	return nil
}

func VerifyEvidenceBundle(bundle skil.EvidenceBundle, trustedKeys map[string]string) error {
	if bundle.Signature == nil {
		return errors.New("evidence bundle signature is missing")
	}
	payload, err := evidencePayload(bundle)
	if err != nil {
		return err
	}
	return verify(payload, *bundle.Signature, trustedKeys)
}

func attestationPayload(attestation skil.Attestation) ([]byte, error) {
	attestation.Signature = nil
	return CanonicalJSON(attestation)
}

func evidencePayload(bundle skil.EvidenceBundle) ([]byte, error) {
	bundle.Signature = nil
	return CanonicalJSON(bundle)
}

func packagePayload(statement skil.PackageStatement) ([]byte, error) {
	statement.Signature = nil
	return CanonicalJSON(statement)
}

// CanonicalJSON serializes v into a canonical JSON form that any
// independent verifier can reproduce from the wire bytes alone, without
// knowing skil's internal Go struct shapes. Go's encoding/json marshals a
// struct in its *declaration order*, which is stable for a fixed version of
// skil but not self-describing — a verifier living in another repository
// (skpm, SkillForge) would have to mirror skil's exact struct definitions,
// field for field, to reproduce byte-identical signed payloads, and would
// silently break on any future schema change.
//
// Canonicalization removes that coupling: v is marshaled normally (so
// type-specific encoding, e.g. RFC 3339 timestamps, is preserved), then
// decoded into a generic any using json.Number (so numeric literals keep
// their exact original digit sequence instead of being coerced through
// float64) and re-marshaled. encoding/json marshals map[string]any with
// keys sorted lexicographically, which makes the result independent of
// struct field order — an external verifier only needs the JSON object
// itself (with the "signature" field removed) and this same two-step
// canonicalization to recompute the exact bytes that were signed.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

func verify(payload []byte, signature skil.Signature, trustedKeys map[string]string) error {
	if signature.Provider != Provider || !strings.EqualFold(signature.Algorithm, Algorithm) {
		return fmt.Errorf("unsupported signature provider or algorithm %q/%q", signature.Provider, signature.Algorithm)
	}
	encodedKey, ok := trustedKeys[signature.KeyID]
	if !ok {
		return fmt.Errorf("untrusted signing key %q", signature.KeyID)
	}
	publicKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("trusted key %q is not a valid base64 Ed25519 public key", signature.KeyID)
	}
	value, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil || len(value) != ed25519.SignatureSize {
		return errors.New("signature value is not valid base64 Ed25519 data")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, value) {
		return errors.New("cryptographic signature verification failed")
	}
	return nil
}
