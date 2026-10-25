package schemas

import "testing"

func TestExplanationSchemaAcceptsCanonicalOutput(t *testing.T) {
	document := []byte(`{
  "schema_version":"1.0.0",
  "artifact":{"name":"example","content_manifest_sha256":"abc"},
  "status":"WARN","verdict":"REVIEW","authoritative":false,
  "summary":"review required",
  "issues":[{"kind":"budget","title":"Budget","explanation":"wall_time"}],
  "coverage":[{"name":"static","state":"completed"}],
  "next_actions":["rerun"]
}`)
	if err := ValidateYAML("explanation-v1.schema.json", document); err != nil {
		t.Fatal(err)
	}
}

func TestExplanationSchemaRejectsUnknownTopLevelField(t *testing.T) {
	document := []byte(`{"schema_version":"1.0.0","artifact":{"name":"x","content_manifest_sha256":"abc"},"status":"PASS","verdict":"CLEAR","authoritative":true,"summary":"ok","issues":[],"coverage":[],"next_actions":[],"unsafe_override":true}`)
	if err := ValidateYAML("explanation-v1.schema.json", document); err == nil {
		t.Fatal("unknown explanation field was accepted")
	}
}
