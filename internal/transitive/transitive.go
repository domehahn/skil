// Package transitive implements Transitive External Reference Scanning:
// an opt-in (always off unless explicitly requested — skil's offline
// guarantee for a plain scan is unaffected), bounded traversal of the
// external HTTPS references a skill's own content points at.
//
//	SKILL.md
//	   └── "download and use: https://example.com/helper.md"
//	                              │
//	                              ▼
//	                         helper.md
//	                              │
//	                              └── https://evil.example/payload.py
//
// A skill can instruct an agent to fetch and use content skil's own static
// scan of the root artifact never sees. This package extracts candidate
// references, fetches each one (through a caller-supplied Fetcher — this
// package has no direct network access itself, keeping the fetch's own
// security boundary, host allowlisting, and byte bounds entirely the
// caller's responsibility), and recursively scans what was fetched with
// the caller-supplied Scanner (ordinarily the exact same registry.Scan
// used for the root artifact), building a full reference graph: every
// reference found is recorded, whether it was followed or skipped, and
// why.
package transitive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/assurance"
	"github.com/domehahn/skil/pkg/skil"
)

const (
	// DefaultDepth is how many reference hops are followed when --transitive
	// is set without an explicit depth: only references the root artifact
	// itself contains, not references of references.
	DefaultDepth = 1
	// MaxAllowedDepth is a hard ceiling regardless of what a caller
	// requests, so a deeply chained reference graph cannot make traversal
	// unbounded even if every other budget dimension were misconfigured.
	MaxAllowedDepth = 3
	// DefaultMaxTargets bounds the total number of distinct references
	// followed across the whole traversal (not per artifact).
	DefaultMaxTargets = 32
	// DefaultMaxDownloadBytes bounds the total bytes fetched across every
	// followed reference combined.
	DefaultMaxDownloadBytes int64 = 10 << 20
	// DefaultMaxTraversalTime bounds total wall-clock time spent
	// traversing references (extraction + every fetch + every child scan).
	DefaultMaxTraversalTime = 60 * time.Second
)

// externalURL matches a bare https:// reference in text content. It
// deliberately does not try to distinguish "meant to be fetched and used"
// from "just a documentation link" — that distinction is exactly what
// skil cannot make statically and safely, so every candidate is recorded
// and it is the allow/deny prefix policy (Options) that decides which
// ones are actually followed.
var externalURL = regexp.MustCompile(`https://[^\s"'<>()\[\]` + "`" + `]+`)

// Options configures one traversal. Zero values (Depth <= 0,
// MaxTargets <= 0, MaxDownloadBytes <= 0, MaxTraversalTime <= 0) fall back
// to the corresponding Default.
type Options struct {
	Depth            int
	AllowPrefixes    []string
	DenyPrefixes     []string
	MaxTargets       int
	MaxDownloadBytes int64
	MaxTraversalTime time.Duration
}

// FetchResult is what a Fetcher returns for one successfully fetched
// reference.
type FetchResult struct {
	// Path is a local file or directory path artifact.Load can consume.
	Path string
	// BytesUsed is how much of the shared download budget this fetch
	// consumed — not necessarily len(file), since a Fetcher may itself
	// enforce its own per-request limit independently.
	BytesUsed int64
	// Cleanup removes any temporary files Fetcher created; always called
	// once the caller is done with Path, even on a later scan failure.
	Cleanup func()
}

// Fetcher retrieves one reference URL. remainingBudget is the caller's
// current total download-byte budget remaining across the whole
// traversal; a Fetcher must not use more than that. All of the actual
// network security boundary (scheme/host validation, private-address
// rejection, redirect handling, TLS, timeouts) is the Fetcher
// implementation's responsibility — this package only orchestrates when
// and whether to call it.
type Fetcher func(ctx context.Context, url string, remainingBudget int64) (FetchResult, error)

// Scanner runs the ordinary scan pipeline (ordinarily registry.Scan) on a
// path a Fetcher produced.
type Scanner func(ctx context.Context, path string) (skil.ScanResult, error)

// ExtractReferences finds every distinct candidate https:// reference in
// an artifact's files, sorted for deterministic output. It scans every
// file's raw content, not only text-classified ones — a reference
// embedded somewhere unusual is still a reference worth recording, and
// the regex itself cannot false-positive-match binary noise into
// something that would ever pass a real URL fetch.
func ExtractReferences(artifact skil.Artifact) []string {
	seen := map[string]bool{}
	var out []string
	for _, file := range artifact.Files {
		for _, match := range externalURL.FindAllString(string(file.Data), -1) {
			url := strings.TrimRight(match, ".,;:!?)]}\"'")
			if url == "" || seen[url] {
				continue
			}
			seen[url] = true
			out = append(out, url)
		}
	}
	sort.Strings(out)
	return out
}

// permitted reports whether url is allowed to be followed under the
// allow/deny prefix policy: a deny match always wins; otherwise, an empty
// allow-list permits everything, and a non-empty one requires a match.
func permitted(url string, allow, deny []string) bool {
	for _, prefix := range deny {
		if prefix != "" && strings.HasPrefix(url, prefix) {
			return false
		}
	}
	if len(allow) == 0 {
		return true
	}
	for _, prefix := range allow {
		if prefix != "" && strings.HasPrefix(url, prefix) {
			return true
		}
	}
	return false
}

type budget struct {
	targetsRemaining int
	bytesRemaining   int64
	deadline         time.Time
}

func (b *budget) exhausted() bool {
	return b.targetsRemaining <= 0 || b.bytesRemaining <= 0 || !time.Now().Before(b.deadline)
}

// Run traverses root's references (and, up to opts.Depth, references of
// references) using fetch and scan, and returns the full reference graph
// — every distinct reference found across the whole traversal, each
// either successfully fetched-and-scanned or recorded with a specific
// SkipReason.
func Run(ctx context.Context, root skil.Artifact, opts Options, fetch Fetcher, scan Scanner) []skil.ReferenceNode {
	depth := opts.Depth
	if depth <= 0 {
		depth = DefaultDepth
	}
	if depth > MaxAllowedDepth {
		depth = MaxAllowedDepth
	}
	maxTargets := opts.MaxTargets
	if maxTargets <= 0 {
		maxTargets = DefaultMaxTargets
	}
	maxBytes := opts.MaxDownloadBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxDownloadBytes
	}
	maxTime := opts.MaxTraversalTime
	if maxTime == 0 {
		maxTime = DefaultMaxTraversalTime
	} else if maxTime < 0 {
		maxTime = 0
	}
	b := &budget{targetsRemaining: maxTargets, bytesRemaining: maxBytes, deadline: time.Now().Add(maxTime)}

	seen := map[string]bool{}
	var nodes []skil.ReferenceNode

	var walk func(artifact skil.Artifact, parentURL string, currentDepth int)
	walk = func(artifact skil.Artifact, parentURL string, currentDepth int) {
		if currentDepth > depth {
			return
		}
		for _, url := range ExtractReferences(artifact) {
			if seen[url] {
				nodes = append(nodes, skil.ReferenceNode{
					URL: url, ParentURL: parentURL, Depth: currentDepth, AlreadyDiscovered: true,
				})
				continue
			}
			seen[url] = true
			node := skil.ReferenceNode{URL: url, ParentURL: parentURL, Depth: currentDepth}

			if !permitted(url, opts.AllowPrefixes, opts.DenyPrefixes) {
				node.SkipReason = "not permitted by transitive allow/deny prefix policy"
				nodes = append(nodes, node)
				continue
			}
			if b.exhausted() {
				node.SkipReason = "transitive traversal budget exhausted (targets, bytes, or time)"
				nodes = append(nodes, node)
				continue
			}
			if ctx.Err() != nil {
				node.SkipReason = "context cancelled"
				nodes = append(nodes, node)
				continue
			}

			result, err := fetch(ctx, url, b.bytesRemaining)
			if err != nil {
				node.SkipReason = "fetch failed: " + err.Error()
				nodes = append(nodes, node)
				continue
			}
			b.targetsRemaining--
			b.bytesRemaining -= result.BytesUsed

			childScan, scanErr := scan(ctx, result.Path)
			if result.Cleanup != nil {
				result.Cleanup()
			}
			if scanErr != nil {
				node.SkipReason = "scan failed: " + scanErr.Error()
				nodes = append(nodes, node)
				continue
			}
			node.Fetched = true
			node.Digest = childScan.Artifact.SubjectDigest()
			node.Scan = &childScan
			nodes = append(nodes, node)

			if currentDepth < depth {
				walk(childScan.Artifact, url, currentDepth+1)
			} else {
				for _, unresolved := range ExtractReferences(childScan.Artifact) {
					nodes = append(nodes, skil.ReferenceNode{
						URL: unresolved, ParentURL: url, Depth: currentDepth + 1,
						SkipReason: "maximum transitive depth exceeded",
					})
				}
			}
		}
	}
	walk(root, "", 1)
	return nodes
}

// BuildAssuranceClosure constructs the deterministic AssuranceClosure graph from the root artifact and reference nodes.
func BuildAssuranceClosure(root skil.Artifact, refNodes []skil.ReferenceNode) skil.AssuranceClosure {
	return BuildAssuranceClosureFromScan(skil.ScanResult{
		Artifact: root, Status: skil.StatusPass, Verdict: skil.VerdictClear,
		Maximum: skil.SeverityInfo,
	}, refNodes)
}

// BuildAssuranceClosureFromScan includes the root's actual scan state in the
// graph so closure evaluation cannot accidentally treat a blocked root as safe.
func BuildAssuranceClosureFromScan(rootScan skil.ScanResult, refNodes []skil.ReferenceNode) skil.AssuranceClosure {
	root := rootScan.Artifact
	rootNode := skil.ClosureNode{
		ID:              root.SubjectDigest(),
		Kind:            skil.NodeRoot,
		Source:          root.Source,
		Digest:          root.SubjectDigest(),
		Depth:           0,
		ScanStatus:      string(rootScan.Status),
		MaximumSeverity: rootScan.Maximum,
		Verdict:         string(rootScan.Verdict),
		Required:        true,
		Resolved:        true,
		Analyzed:        true,
		AnalysisStatus:  scanAnalysisStatus(rootScan),
		Verification:    skil.VerificationVerified,
	}

	localNodes, localEdges := localArtifactNodes(rootScan)
	nodes := append([]skil.ClosureNode{rootNode}, localNodes...)
	var edges []skil.ClosureEdge
	edges = append(edges, localEdges...)
	var limitations []string
	complete := true
	maxSev := skil.SeverityInfo

	for _, ref := range refNodes {
		parentID := root.SubjectDigest()
		if ref.ParentURL != "" {
			parentID = ref.ParentURL
		}
		edges = append(edges, skil.ClosureEdge{FromID: parentID, ToID: ref.URL, Relation: "references"})
		if ref.AlreadyDiscovered {
			continue
		}
		node := skil.ClosureNode{
			ID:       ref.URL,
			Kind:     skil.NodeExternalReference,
			Source:   ref.URL,
			Depth:    ref.Depth,
			Required: true,
		}

		node.ParentDigest = parentID

		if ref.Fetched && ref.Scan != nil {
			node.Digest = ref.Digest
			node.ScanStatus = string(ref.Scan.Status)
			node.MaximumSeverity = ref.Scan.Maximum
			node.Verdict = string(ref.Scan.Verdict)
			node.Resolved = true
			node.Analyzed = true
			node.AnalysisStatus = scanAnalysisStatus(*ref.Scan)
			node.Verification = skil.VerificationVerified

			for _, f := range ref.Scan.Findings {
				findingProv := fmt.Sprintf("%s#%s@%s", ref.URL, f.ID, f.Location.File)
				node.Findings = append(node.Findings, findingProv)
			}

			if severityRank(ref.Scan.Maximum) > severityRank(maxSev) {
				maxSev = ref.Scan.Maximum
			}
			if node.AnalysisStatus != skil.AnalysisCompleted {
				complete = false
				limitations = append(limitations, fmt.Sprintf("%s: child analysis incomplete", ref.URL))
			}
		} else {
			complete = false
			node.Resolved = false
			node.Analyzed = false
			node.AnalysisStatus = skil.AnalysisNotRun
			node.Verification = skil.VerificationUnresolved
			if ref.SkipReason != "" {
				node.ScanStatus = "skipped"
				node.Verdict = "UNRESOLVED"
				limitations = append(limitations, fmt.Sprintf("%s: %s", ref.URL, ref.SkipReason))
			}
		}

		nodes = append(nodes, node)
	}

	closure := skil.AssuranceClosure{
		RootDigest:      root.SubjectDigest(),
		Nodes:           nodes,
		Edges:           edges,
		MaximumSeverity: maxSev,
		Complete:        complete,
		Limitations:     limitations,
	}
	return assurance.Finalize(closure)
}

func localArtifactNodes(scan skil.ScanResult) ([]skil.ClosureNode, []skil.ClosureEdge) {
	persistentFiles := map[string]bool{}
	for _, observation := range scan.Observations {
		if observation.Capability == "memory.persistence" || observation.Capability == "memory.cross_session" {
			persistentFiles[observation.Location.File] = true
		}
	}
	var nodes []skil.ClosureNode
	var edges []skil.ClosureEdge
	for _, file := range scan.Artifact.Files {
		kind, relation := classifyLocalNode(file, persistentFiles[file.Path])
		status := fileAnalysisStatus(file.Path, scan)
		maximum := skil.SeverityInfo
		verdict := skil.VerdictClear
		var findingRefs []string
		for _, finding := range scan.Findings {
			if finding.Suppressed || finding.Location.File != file.Path {
				continue
			}
			findingRefs = append(findingRefs, finding.ID+"@"+file.Path)
			if severityRank(finding.Severity) > severityRank(maximum) {
				maximum = finding.Severity
			}
		}
		if severityRank(maximum) >= severityRank(skil.SeverityHigh) {
			verdict = skil.VerdictBlock
		} else if severityRank(maximum) >= severityRank(skil.SeverityMedium) {
			verdict = skil.VerdictReview
		}
		scanStatus := skil.StatusPass
		if verdict == skil.VerdictBlock {
			scanStatus = skil.StatusFail
		} else if verdict == skil.VerdictReview || status != skil.AnalysisCompleted {
			scanStatus = skil.StatusWarn
		}
		digest := file.SHA256
		if digest == "" {
			sum := sha256.Sum256(file.Data)
			digest = hex.EncodeToString(sum[:])
		}
		id := string(kind) + ":" + file.Path
		nodes = append(nodes, skil.ClosureNode{
			ID: id, Kind: kind, Source: file.Path, Digest: digest,
			ParentDigest: scan.Artifact.SubjectDigest(), Depth: 1, ScanStatus: string(scanStatus),
			MaximumSeverity: maximum, Verdict: string(verdict), Required: true,
			Resolved: digest != "", Analyzed: status == skil.AnalysisCompleted,
			Findings: findingRefs, AnalysisStatus: status, Verification: skil.VerificationVerified,
		})
		edges = append(edges, skil.ClosureEdge{FromID: scan.Artifact.SubjectDigest(), ToID: id, Relation: relation})
	}
	return nodes, edges
}

func classifyLocalNode(file skil.File, persistent bool) (skil.NodeKind, string) {
	clean := strings.ToLower(strings.ReplaceAll(file.Path, "\\", "/"))
	base := clean
	if slash := strings.LastIndexByte(clean, '/'); slash >= 0 {
		base = clean[slash+1:]
	}
	if file.ContainerDepth > 0 {
		return skil.NodeNestedArtifact, "contains"
	}
	if persistent {
		return skil.NodePersistentState, "configures"
	}
	if strings.Contains(clean, ".claude/") || strings.Contains(clean, ".cursor/") || strings.Contains(clean, ".codex/") || strings.HasSuffix(clean, "hooks/hooks.json") {
		return skil.NodeAgentSurface, "configures"
	}
	if strings.Contains(base, "mcp") && (strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")) {
		return skil.NodeMCPSurface, "loads"
	}
	if isDependencyArtifact(clean, base) {
		return skil.NodeDependency, "depends-on"
	}
	return skil.NodeArtifact, "contains"
}

func isDependencyArtifact(clean, base string) bool {
	if strings.Contains(clean, ".cargo/config.toml") {
		return true
	}
	for _, name := range []string{"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pyproject.toml", "poetry.lock", "uv.lock", "requirements.txt", "pip.conf", ".npmrc", "cargo.toml", "cargo.lock", "pom.xml", "settings.xml", "go.mod", "go.sum"} {
		if base == name {
			return true
		}
	}
	return false
}

func fileAnalysisStatus(path string, scan skil.ScanResult) skil.AnalysisStatus {
	completed := false
	for _, item := range scan.Inspection {
		if item.File != path {
			continue
		}
		switch item.Outcome {
		case skil.InspectionFailed:
			return skil.AnalysisFailed
		case skil.InspectionSkipped:
			return skil.AnalysisIncomplete
		case skil.InspectionCompleted:
			completed = true
		}
	}
	for _, record := range scan.Analyzability {
		if record.Path == path && record.State == skil.AnalyzabilityOpaque {
			return skil.AnalysisIncomplete
		}
	}
	if completed || len(scan.Inspection) == 0 {
		return skil.AnalysisCompleted
	}
	return skil.AnalysisIncomplete
}

// ComputeClosureDigest produces a deterministic, ordering-independent SHA-256 digest of the closure.
func ComputeClosureDigest(closure skil.AssuranceClosure) string {
	return assurance.ComputeDigest(closure)
}

func scanAnalysisStatus(scan skil.ScanResult) skil.AnalysisStatus {
	if scan.Status == skil.StatusError || scan.Completeness.Failed > 0 {
		return skil.AnalysisFailed
	}
	if len(scan.Budget.Exceeded) > 0 || scan.Completeness.Skipped > 0 || scan.Completeness.Failed > 0 ||
		(scan.Completeness.Applicable > 0 && scan.Completeness.Completeness < 1) {
		return skil.AnalysisIncomplete
	}
	return skil.AnalysisCompleted
}

func severityRank(s skil.Severity) int {
	switch s {
	case skil.SeverityCritical:
		return 4
	case skil.SeverityHigh:
		return 3
	case skil.SeverityMedium:
		return 2
	case skil.SeverityLow:
		return 1
	default:
		return 0
	}
}
