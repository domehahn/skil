package reputation

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedOfflineReputationPositiveAndNegative(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reputation.json")
	data := []byte(`{"version":1,"packages":[
{"ecosystem":"PyPI","name":"legacy-demo","abandoned":true,"last_update":"2014-01-01T00:00:00Z"},
{"ecosystem":"PyPI","name":"maintained-demo","abandoned":false,"last_update":"2026-01-01T00:00:00Z"}
]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	abandoned, err := provider.Reputation(context.Background(), "PyPI", "legacy-demo")
	if err != nil || !abandoned.Abandoned {
		t.Fatalf("abandoned record missing: %#v %v", abandoned, err)
	}
	maintained, err := provider.Reputation(context.Background(), "PyPI", "maintained-demo")
	if err != nil || maintained.Abandoned {
		t.Fatalf("maintained package marked abandoned: %#v %v", maintained, err)
	}
}

func TestTrustedOfflineReputationRejectsMalformedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reputation.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"packages":[],"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("malformed reputation evidence must fail closed")
	}
}

func TestBuiltinReputationIsVersionedAndDetectsPycryptoOffline(t *testing.T) {
	provider, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	record, err := provider.Reputation(context.Background(), "PyPI", "pycrypto")
	if err != nil {
		t.Fatal(err)
	}
	if !record.Abandoned {
		t.Fatal("built-in pycrypto abandonment evidence is missing")
	}
	unknown, err := provider.Reputation(context.Background(), "PyPI", "cryptography")
	if err != nil || unknown.Abandoned {
		t.Fatalf("unknown maintained package was marked abandoned: %#v %v", unknown, err)
	}
}
