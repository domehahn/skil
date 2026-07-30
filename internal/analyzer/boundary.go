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
		rule("SKIL-BOUNDARY-SSRF-INTERNAL", "Request targets an internal or loopback address", "network-boundary", skil.SeverityMedium,
			`(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|fetch|axios\.(?:get|post)|http\.(?:get|request)|curl)\s*\(?[^\n]{0,60}(?:https?://)?(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})`,
			"A server-side request primitive targets a hardcoded internal, loopback, or private-network address.",
			"Route internal traffic through an explicit, reviewed service boundary rather than a hardcoded internal address."),
		rule("SKIL-BOUNDARY-CONTAINER", "Container control-plane access", "infrastructure-boundary", skil.SeverityCritical,
			`(?:/var/run/docker\.sock|/run/containerd/containerd\.sock|KUBERNETES_SERVICE_HOST|/var/run/secrets/kubernetes\.io/serviceaccount|docker\.from_env\s*\()`,
			"Content accesses a container or orchestration control plane.",
			"Remove control-plane access or use a dedicated least-privilege broker with an explicit operation allowlist."),
		rule("SKIL-BOUNDARY-AGENT-STATE", "Peer-agent state surveillance", "agent-boundary", skil.SeverityHigh,
			`(?:read|open|scan|collect|upload|watch).{0,100}(?:\.codex|\.claude|\.cursor|\.gemini|\.continue|agent[_ -]?(?:history|memory|session|transcript)|conversation[_ -]?(?:history|log))`,
			"Instructions or code access another agent's private state, history, or control files.",
			"Restrict reads to the current artifact and exchange data only through an explicit, auditable interface."),
		rule("SKIL-BOUNDARY-MCP-CONFIG", "Agent MCP configuration snooping", "agent-boundary", skil.SeverityHigh,
			`(?:open|read|access|load|inspect|cat|less|head|grep)\s*\(?['"]?[^\n]{0,60}mcp(?:_config)?\.json|\.(?:codex|claude|gemini|cursor)/mcp(?:_config)?\.json|(?:list|enumerate|discover)\s+(?:all\s+)?(?:available\s+)?mcp\s+(?:servers?|tools?|services?)|mcp(?:_config)?\.json[^\n]{0,80}(?:api[_ -]?key|token|secret|url|endpoint)`,
			"Content reads or enumerates the broader agent's MCP server configuration rather than the skill's own declared MCP manifest.",
			"Restrict access to the skill's own declared MCP configuration; do not read or enumerate other MCP server config."),
		rule("SKIL-BOUNDARY-PEER-SKILL", "Peer skill enumeration or access", "agent-boundary", skil.SeverityMedium,
			`(?:os\.listdir|os\.scandir|glob\.glob|Path\.iterdir|ls|find)\s*\(?[^\n]{0,60}\.(?:codex|claude|gemini|cursor)/skills?|(?:read|access|inspect|enumerate|list|discover|find|identify)\s+(?:all\s+)?(?:other\s+|installed\s+|available\s+){1,3}skills?(?:\s+in\s+(?:the\s+)?(?:skills?|agent)\s+(?:directory|folder))?`,
			"Content enumerates or reads sibling skills' directories or manifests rather than operating within its own scope.",
			"Restrict discovery to the current skill; do not enumerate or read other installed skills."),
		rule("SKIL-BOUNDARY-CLOUD-EXFIL", "Sensitive data transfer to cloud object storage", "data-boundary", skil.SeverityCritical,
			`(?:(?:aws\s+s3|gsutil|gcloud\s+storage|azcopy|rclone)\s+(?:cp|copy|sync).{0,100}(?:s3://|gs://|https://[^ ]+\.blob\.core\.windows\.net)|(?:secret|credential|api.?key|environment).{0,100}(?:s3://|gs://|blob\.core\.windows\.net))`,
			"Content transfers potentially sensitive data to a cloud object-storage destination.",
			"Remove the transfer or allowlist an exact destination and redact secrets before upload."),
		rule("SKIL-BOUNDARY-CLOUD-SDK-UPLOAD", "Cloud object-storage SDK upload", "data-boundary", skil.SeverityMedium,
			`\.(?:put_object|upload_fileobj|upload_file|upload_from_filename|upload_from_string|upload_from_file|upload_blob)\s*\(`,
			"Code calls a cloud storage SDK method that uploads data to object storage.",
			"Declare and constrain the exact destination bucket/container and review the uploaded data for sensitive content."),
		rule("SKIL-BOUNDARY-CONTAINER-ESCAPE", "Privileged container or host-namespace access", "infrastructure-boundary", skil.SeverityCritical,
			`(?:docker|podman)\s+run.{0,160}(?:--privileged|--pid[= ]host|--network[= ]host|--volume[= ]/(?:\s|:)|--cap-add[= ]?(?:sys_admin|sys_ptrace|net_admin))|(?:privileged|hostNetwork|hostPID|hostIPC|allowPrivilegeEscalation|automountServiceAccountToken)\s*:\s*true|runAsUser\s*:\s*0\b|(?:add|capabilities)\s*:\s*\[[^\]]*(?:SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE)[^\]]*\]|hostPath\s*:\s*(?:\n\s*)?path\s*:\s*/(?:\s|$)|\bnsenter\b.{0,60}--(?:target|mount|uts|ipc|net|pid)|\bunshare\s+(?:--user|--mount|--pid|--uts|--net)\b|release_agent\s*=|/sys/fs/cgroup/[^\n]{0,60}release_agent`,
			"Content enables privileged container execution, a host namespace, a root host mount, or grants a dangerous Linux capability.",
			"Use a non-root container with dropped capabilities, isolated namespaces, and narrow read-only mounts."),
		rule("SKIL-BOUNDARY-MUTABLE-IMAGE", "Mutable container image reference", "supply-chain-integrity", skil.SeverityHigh,
			`(?:docker|podman)\s+pull\s+[A-Za-z0-9._/-]+(?::latest)?(?:\s|$)|image\s*:\s*[A-Za-z0-9._/-]+(?::latest)?\s*$`,
			"Content pulls or deploys a container image without an immutable digest.",
			"Pin the image by verified sha256 digest and enforce signature verification."),
		rule("SKIL-IAC-WILDCARD-POLICY", "Wildcard IAM policy action", "infrastructure-boundary", skil.SeverityCritical,
			// Scoped to the action value being the bare wildcard "*"
			// specifically (not e.g. "s3:*", a common and often legitimate
			// service-scoped wildcard) — "any action whatsoever" is the
			// well-established dangerous pattern (cf. Checkov/cfn-nag),
			// not merely a wildcard anywhere in a policy statement.
			`"?[Aa]ctions?"?\s*[:=]\s*\[?\s*"\*"\s*\]?`,
			"An Infrastructure-as-Code IAM/policy statement grants permission to perform any action whatsoever.",
			"Scope the policy to exact, named actions; never grant a bare action wildcard."),
		rule("SKIL-IAC-OPEN-CIDR", "Unrestricted full-internet CIDR range", "infrastructure-boundary", skil.SeverityMedium,
			// Field names used for both ingress and egress rules across
			// Terraform/CloudFormation/GCP, so this cannot reliably
			// distinguish direction from a single line; kept at Medium
			// (advisory) severity rather than asserting "ingress"
			// specifically, since egress-to-anywhere is comparatively
			// more common and less severe than open ingress.
			`(?:cidr_blocks?|CidrIp|source_range)s?\s*[:=]\s*\[?\s*"?0\.0\.0\.0/0"?`,
			"An Infrastructure-as-Code network rule references the full-internet CIDR range 0.0.0.0/0.",
			"Scope the rule to specific, reviewed CIDR ranges rather than 0.0.0.0/0; confirm whether this is an ingress or egress rule and whether that exposure is intended."),
	}}
}

func (b *Boundary) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.boundary", Version: "1.0.0",
		Domain: "runtime-infra", Subdomain: "container-escape",
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
