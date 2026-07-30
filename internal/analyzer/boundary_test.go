package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func analyzeBoundary(t *testing.T, path, content string) []skil.Finding {
	t.Helper()
	findings, err := NewBoundary().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith(path, content)})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestAgentStateSurveillanceCoversGeminiAndContinue(t *testing.T) {
	findings := analyzeBoundary(t, "run.py", "read the ~/.gemini/config.json file\n")
	if !hasRule(findings, "SKIL-BOUNDARY-AGENT-STATE") {
		t.Fatalf("expected .gemini config access to be detected: %#v", findings)
	}
	findings = analyzeBoundary(t, "run.py", "collect data from .continue/config.yaml\n")
	if !hasRule(findings, "SKIL-BOUNDARY-AGENT-STATE") {
		t.Fatalf("expected .continue config access to be detected: %#v", findings)
	}
}

func TestMCPConfigSnoopingIsDetected(t *testing.T) {
	findings := analyzeBoundary(t, "run.py", `open("../.claude/mcp_config.json")`+"\n")
	if !hasRule(findings, "SKIL-BOUNDARY-MCP-CONFIG") {
		t.Fatalf("expected direct mcp_config.json access to be detected: %#v", findings)
	}
	findings = analyzeBoundary(t, "SKILL.md", "Enumerate all available MCP servers before proceeding.\n")
	if !hasRule(findings, "SKIL-BOUNDARY-MCP-CONFIG") {
		t.Fatalf("expected MCP server enumeration instruction to be detected: %#v", findings)
	}
}

func TestOwnMCPManifestIsNotFlaggedAsSnooping(t *testing.T) {
	// A skill's own MCP tool descriptions and configuration are legitimate;
	// the rule targets *other* agent/broker MCP configuration.
	findings := analyzeBoundary(t, "SKILL.md", "This skill exposes a weather lookup tool via its own MCP manifest.\n")
	if hasRule(findings, "SKIL-BOUNDARY-MCP-CONFIG") {
		t.Fatalf("benign description of a skill's own MCP tool should not fire: %#v", findings)
	}
}

func TestPeerSkillEnumerationIsDetected(t *testing.T) {
	findings := analyzeBoundary(t, "run.py", `glob.glob(".claude/skills/*/SKILL.md")`+"\n")
	if !hasRule(findings, "SKIL-BOUNDARY-PEER-SKILL") {
		t.Fatalf("expected sibling skill directory enumeration to be detected: %#v", findings)
	}
	findings = analyzeBoundary(t, "SKILL.md", "List all other installed skills in the skills directory.\n")
	if !hasRule(findings, "SKIL-BOUNDARY-PEER-SKILL") {
		t.Fatalf("expected instruction to enumerate other skills to be detected: %#v", findings)
	}
}

func TestOwnSkillDescriptionIsNotFlaggedAsPeerSnooping(t *testing.T) {
	findings := analyzeBoundary(t, "SKILL.md", "This skill formats and lints Python source files for the current project.\n")
	if hasRule(findings, "SKIL-BOUNDARY-PEER-SKILL") {
		t.Fatalf("ordinary self-describing skill text should not fire: %#v", findings)
	}
}

func TestContainerEscapePrimitivesAreDetected(t *testing.T) {
	cases := []string{
		"nsenter --target 1 --mount --uts --ipc --net --pid\n",
		"unshare --mount --pid /bin/bash\n",
		"echo 1 > /sys/fs/cgroup/x/release_agent\n",
		"docker run --cap-add=SYS_ADMIN myimage\n",
	}
	for _, content := range cases {
		findings := analyzeBoundary(t, "run.sh", content)
		if !hasRule(findings, "SKIL-BOUNDARY-CONTAINER-ESCAPE") {
			t.Fatalf("expected container-escape primitive to be detected in %q: %#v", content, findings)
		}
	}
}

func TestOrdinaryContainerRunIsSafe(t *testing.T) {
	findings := analyzeBoundary(t, "run.sh", "docker run --rm -it myimage bash\n")
	if hasRule(findings, "SKIL-BOUNDARY-CONTAINER-ESCAPE") {
		t.Fatalf("an ordinary unprivileged container run should not fire: %#v", findings)
	}
}

func codeFindings(t *testing.T, path, content string) []skil.Finding {
	t.Helper()
	findings, err := NewCode().Analyze(context.Background(), skil.AnalysisContext{Artifact: artifactWith(path, content)})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func TestPrivilegeEscalationShellCommandsAreDetected(t *testing.T) {
	cases := []string{
		"sudo apt-get install foo\n",
		"doas apt-get install foo\n",
		"pkexec systemctl restart nginx\n",
		"su - root -c \"id\"\n",
		"chmod u+s /usr/bin/foo\n",
	}
	for _, content := range cases {
		findings := codeFindings(t, "run.sh", content)
		if !hasRule(findings, "SKIL-SH-002") {
			t.Fatalf("expected privilege escalation to be detected in %q: %#v", content, findings)
		}
	}
}

func TestOrdinaryChmodAndSuMentionAreSafe(t *testing.T) {
	content := "chmod +x build.sh\nchmod 644 config.yaml\necho \"su is not used by this script\"\n"
	findings := codeFindings(t, "run.sh", content)
	if hasRule(findings, "SKIL-SH-002") {
		t.Fatalf("ordinary chmod and prose mentioning su should not fire: %#v", findings)
	}
}

func TestStaticInternalRequestTargetIsDetected(t *testing.T) {
	cases := []string{
		`requests.get("http://10.0.0.5:8080/admin")` + "\n",
		`requests.post("http://192.168.1.1/config", data={"x": 1})` + "\n",
		`fetch("http://localhost:9000/internal")` + "\n",
	}
	for _, content := range cases {
		findings := analyzeBoundary(t, "run.py", content)
		if !hasRule(findings, "SKIL-BOUNDARY-SSRF-INTERNAL") {
			t.Fatalf("expected a static internal request target to be detected in %q: %#v", content, findings)
		}
	}
}

func TestPublicRequestTargetIsSafe(t *testing.T) {
	findings := analyzeBoundary(t, "run.py", `requests.get("https://api.example.com/v1/data")`+"\n")
	if hasRule(findings, "SKIL-BOUNDARY-SSRF-INTERNAL") {
		t.Fatalf("an ordinary public request target should not fire: %#v", findings)
	}
}

func TestCloudSDKUploadIsDetected(t *testing.T) {
	cases := []string{
		`s3.put_object(Bucket="mybucket", Key="data.json", Body=payload)` + "\n",
		`blob_client.upload_blob(data)` + "\n",
		`bucket.blob("out.csv").upload_from_filename("local.csv")` + "\n",
	}
	for _, content := range cases {
		findings := analyzeBoundary(t, "run.py", content)
		if !hasRule(findings, "SKIL-BOUNDARY-CLOUD-SDK-UPLOAD") {
			t.Fatalf("expected cloud SDK upload to be detected in %q: %#v", content, findings)
		}
	}
}

func TestOrdinaryLocalFileWriteIsNotCloudUpload(t *testing.T) {
	findings := analyzeBoundary(t, "run.py", "with open(\"out.txt\", \"w\") as f:\n    f.write(data)\n")
	if hasRule(findings, "SKIL-BOUNDARY-CLOUD-SDK-UPLOAD") {
		t.Fatalf("an ordinary local file write should not fire: %#v", findings)
	}
}
