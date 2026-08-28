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
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

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
			}
		}
	}
	walk(root, "", 1)
	return nodes
}

// BuildAssuranceClosure constructs the deterministic AssuranceClosure graph from the root artifact and reference nodes.
func BuildAssuranceClosure(root skil.Artifact, refNodes []skil.ReferenceNode) skil.AssuranceClosure {
	rootNode := skil.ClosureNode{
		ID:              root.SubjectDigest(),
		Source:          root.Source,
		Digest:          root.SubjectDigest(),
		Depth:           0,
		ScanStatus:      "completed",
		MaximumSeverity: skil.SeverityInfo,
		Verdict:         "CLEAR",
		Required:        true,
		Resolved:        true,
		Analyzed:        true,
	}

	nodes := []skil.ClosureNode{rootNode}
	var edges []skil.ClosureEdge
	var limitations []string
	complete := true
	maxSev := skil.SeverityInfo

	for _, ref := range refNodes {
		node := skil.ClosureNode{
			ID:       ref.URL,
			Source:   ref.URL,
			Depth:    ref.Depth,
			Required: true,
		}

		parentID := root.SubjectDigest()
		if ref.ParentURL != "" {
			parentID = ref.ParentURL
		}
		node.ParentDigest = parentID

		edges = append(edges, skil.ClosureEdge{
			FromID:   parentID,
			ToID:     ref.URL,
			Relation: "references",
		})

		if ref.Fetched && ref.Scan != nil {
			node.Digest = ref.Digest
			node.ScanStatus = string(ref.Scan.Status)
			node.MaximumSeverity = ref.Scan.Maximum
			node.Verdict = string(ref.Scan.Verdict)
			node.Resolved = true
			node.Analyzed = true

			for _, f := range ref.Scan.Findings {
				findingProv := fmt.Sprintf("%s#%s@%s", ref.URL, f.ID, f.Location.File)
				node.Findings = append(node.Findings, findingProv)
			}

			if severityRank(ref.Scan.Maximum) > severityRank(maxSev) {
				maxSev = ref.Scan.Maximum
			}
		} else {
			complete = false
			node.Resolved = false
			node.Analyzed = false
			if ref.SkipReason != "" {
				node.ScanStatus = "skipped"
				node.Verdict = "UNRESOLVED"
				limitations = append(limitations, fmt.Sprintf("%s: %s", ref.URL, ref.SkipReason))
			}
		}

		nodes = append(nodes, node)
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Depth != nodes[j].Depth {
			return nodes[i].Depth < nodes[j].Depth
		}
		return nodes[i].ID < nodes[j].ID
	})

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].FromID != edges[j].FromID {
			return edges[i].FromID < edges[j].FromID
		}
		return edges[i].ToID < edges[j].ToID
	})

	sort.Strings(limitations)

	closure := skil.AssuranceClosure{
		RootDigest:      root.SubjectDigest(),
		Nodes:           nodes,
		Edges:           edges,
		MaximumSeverity: maxSev,
		Complete:        complete,
		Limitations:     limitations,
	}

	closure.Digest = ComputeClosureDigest(closure)
	return closure
}

// ComputeClosureDigest produces a deterministic, ordering-independent SHA-256 digest of the closure.
func ComputeClosureDigest(closure skil.AssuranceClosure) string {
	h := sha256.New()
	_, _ = io.WriteString(h, closure.RootDigest+"\n")
	for _, n := range closure.Nodes {
		_, _ = io.WriteString(h, fmt.Sprintf("node:%s|%s|%s|%d|%t|%t|%t|%s|%s\n",
			n.ID, n.Source, n.Digest, n.Depth, n.Required, n.Resolved, n.Analyzed, n.ScanStatus, n.MaximumSeverity))
	}
	for _, e := range closure.Edges {
		_, _ = io.WriteString(h, fmt.Sprintf("edge:%s->%s(%s)\n", e.FromID, e.ToID, e.Relation))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
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
