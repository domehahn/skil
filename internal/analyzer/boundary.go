package analyzer

import (
	"context"
	"regexp"

	"github.com/domehahn/skil/pkg/skil"
)

// Boundary detects concrete accesses to privileged infrastructure boundaries.
// It complements generic pattern and data-flow analysis with narrow,
// high-signal indicators that are meaningful across skill ecosystems.
type Boundary struct {
	rules []RulePattern
}

func NewBoundary() *Boundary {
	rule := func(id, title, category string, severity skil.Severity, expression, description, remediation string) RulePattern {
		return RulePattern{Rule: skil.Rule{
			ID: id, Title: title, Category: category, Severity: severity,
			Description: description, Analysis: "boundary", AppliesTo: []string{"text", "code"},
			Remediation: remediation,
		}, Pattern: regexp.MustCompile("(?i)" + expression), Confidence: .96}
	}
	return &Boundary{rules: []RulePattern{
		rule("SKIL-BOUNDARY-METADATA", "Cloud workload identity endpoint access", "infrastructure-boundary", skil.SeverityCritical,
			`(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254).{0,100}(?:latest|metadata|identity|token|credential)|(?:latest/meta-data|computeMetadata/v1)`,
			"Content accesses a cloud metadata or workload-identity endpoint that may expose credentials.",
			"Block link-local metadata destinations and use an explicitly scoped workload identity."),
		rule("SKIL-BOUNDARY-SSRF", "Untrusted destination reaches server-side request primitive", "network-boundary", skil.SeverityHigh,
			`(?:requests\.(?:get|post|put)|urllib\.request|fetch|axios|http\.(?:get|request)|curl).{0,120}(?:user[_-]?input|request\.(?:args|query|body)|params|stdin|tool[_ .-]?output|mcp[_ .-]?output)`,
			"A server-side request primitive appears to consume an untrusted destination.",
			"Parse the URL, resolve it once, reject private and link-local addresses, and allowlist schemes and hosts."),
		rule("SKIL-BOUNDARY-CONTAINER", "Container control-plane access", "infrastructure-boundary", skil.SeverityCritical,
			`(?:/var/run/docker\.sock|/run/containerd/containerd\.sock|KUBERNETES_SERVICE_HOST|/var/run/secrets/kubernetes\.io/serviceaccount|docker\.from_env\s*\()`,
			"Content accesses a container or orchestration control plane.",
			"Remove control-plane access or use a dedicated least-privilege broker with an explicit operation allowlist."),
		rule("SKIL-BOUNDARY-AGENT-STATE", "Peer-agent state surveillance", "agent-boundary", skil.SeverityHigh,
			`(?:read|open|scan|collect|upload|watch).{0,100}(?:\.codex|\.claude|\.cursor|agent[_ -]?(?:history|memory|session|transcript)|conversation[_ -]?(?:history|log))`,
			"Instructions or code access another agent's private state, history, or control files.",
			"Restrict reads to the current artifact and exchange data only through an explicit, auditable interface."),
		rule("SKIL-BOUNDARY-CLOUD-EXFIL", "Sensitive data transfer to cloud object storage", "data-boundary", skil.SeverityCritical,
			`(?:(?:aws\s+s3|gsutil|gcloud\s+storage|azcopy|rclone)\s+(?:cp|copy|sync).{0,100}(?:s3://|gs://|https://[^ ]+\.blob\.core\.windows\.net)|(?:secret|credential|api.?key|environment).{0,100}(?:s3://|gs://|blob\.core\.windows\.net))`,
			"Content transfers potentially sensitive data to a cloud object-storage destination.",
			"Remove the transfer or allowlist an exact destination and redact secrets before upload."),
		rule("SKIL-BOUNDARY-CONTAINER-ESCAPE", "Privileged container or host-namespace access", "infrastructure-boundary", skil.SeverityCritical,
			`(?:docker|podman)\s+run.{0,160}(?:--privileged|--pid[= ]host|--network[= ]host|--volume[= ]/(?:\s|:))|(?:privileged|hostNetwork|hostPID|hostIPC)\s*:\s*true|hostPath\s*:\s*(?:\n\s*)?path\s*:\s*/(?:\s|$)`,
			"Content enables privileged container execution, a host namespace, or a root host mount.",
			"Use a non-root container with dropped capabilities, isolated namespaces, and narrow read-only mounts."),
		rule("SKIL-BOUNDARY-MUTABLE-IMAGE", "Mutable container image reference", "supply-chain-integrity", skil.SeverityHigh,
			`(?:docker|podman)\s+pull\s+[A-Za-z0-9._/-]+(?::latest)?(?:\s|$)|image\s*:\s*[A-Za-z0-9._/-]+(?::latest)?\s*$`,
			"Content pulls or deploys a container image without an immutable digest.",
			"Pin the image by verified sha256 digest and enforce signature verification."),
	}}
}

func (b *Boundary) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.boundary", Version: "1.0.0",
		Categories:    []string{"infrastructure-boundary", "network-boundary", "agent-boundary"},
		AnalysisTypes: []string{"boundary"}, SupportedTypes: []string{"text"},
	}
}

func (b *Boundary) Rules() []skil.Rule {
	out := make([]skil.Rule, len(b.rules))
	for i := range b.rules {
		out[i] = b.rules[i].Rule
	}
	return out
}

func (b *Boundary) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var findings []skil.Finding
	for _, file := range ac.Artifact.Files {
		if !isText(file) {
			continue
		}
		for lineNumber, text := range lines(file.Data) {
			for _, control := range b.rules {
				if control.Pattern.MatchString(text) {
					findings = append(findings, makeFinding(control, file, lineNumber+1, text))
				}
			}
		}
	}
	return findings, nil
}
