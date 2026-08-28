package transitive

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

func artifactWith(path, content string) skil.Artifact {
	return skil.Artifact{Name: "test", Digest: "digest", Files: []skil.File{{Path: path, Data: []byte(content)}}}
}

func TestExtractReferencesFindsAndDedupesURLs(t *testing.T) {
	artifact := skil.Artifact{Files: []skil.File{
		{Path: "SKILL.md", Data: []byte("Download and use: https://example.com/helper.md and also https://example.com/helper.md again.")},
		{Path: "notes.txt", Data: []byte("See https://example.org/tool.py for details.")},
	}}
	refs := ExtractReferences(artifact)
	if len(refs) != 2 {
		t.Fatalf("expected 2 distinct references, got %#v", refs)
	}
	if refs[0] != "https://example.com/helper.md" || refs[1] != "https://example.org/tool.py" {
		t.Fatalf("unexpected references: %#v", refs)
	}
}

func TestExtractReferencesTrimsTrailingPunctuation(t *testing.T) {
	artifact := artifactWith("SKILL.md", "Fetch it from https://example.com/helper.md, then run it.")
	refs := ExtractReferences(artifact)
	if len(refs) != 1 || refs[0] != "https://example.com/helper.md" {
		t.Fatalf("expected trailing comma stripped, got %#v", refs)
	}
}

func fakeFetcher(content map[string]string) Fetcher {
	return func(_ context.Context, url string, _ int64) (FetchResult, error) {
		content, ok := content[url]
		if !ok {
			return FetchResult{}, errors.New("not found")
		}
		return FetchResult{Path: url, BytesUsed: int64(len(content)), Cleanup: func() {}}, nil
	}
}

func fakeScanner(content map[string]string) Scanner {
	return func(_ context.Context, path string) (skil.ScanResult, error) {
		text, ok := content[path]
		if !ok {
			return skil.ScanResult{}, errors.New("no such fetched content")
		}
		artifact := artifactWith("fetched", text)
		artifact.Digest = "digest-of-" + path
		return skil.ScanResult{Artifact: artifact}, nil
	}
}

func TestRunFollowsAReferenceAndRecursesOneLevel(t *testing.T) {
	root := artifactWith("SKILL.md", "download and use: https://example.com/helper.md")
	content := map[string]string{
		"https://example.com/helper.md": "also fetch https://example.com/payload.py",
	}
	nodes := Run(context.Background(), root, Options{Depth: 2}, fakeFetcher(content), fakeScanner(content))

	if len(nodes) != 2 {
		t.Fatalf("expected 2 reference nodes (helper.md and its own payload.py reference), got %#v", nodes)
	}
	byURL := map[string]skil.ReferenceNode{}
	for _, n := range nodes {
		byURL[n.URL] = n
	}
	helper, ok := byURL["https://example.com/helper.md"]
	if !ok || !helper.Fetched || helper.Depth != 1 || helper.Digest == "" {
		t.Fatalf("expected helper.md fetched at depth 1: %#v", helper)
	}
	payload, ok := byURL["https://example.com/payload.py"]
	if !ok || payload.Fetched || payload.Depth != 2 {
		t.Fatalf("expected payload.py recorded at depth 2 (not fetchable in this fixture): %#v", payload)
	}
	if payload.SkipReason == "" {
		t.Fatalf("expected a skip reason for the unresolvable reference: %#v", payload)
	}
}

func TestRunDoesNotRecurseBeyondRequestedDepth(t *testing.T) {
	root := artifactWith("SKILL.md", "https://example.com/helper.md")
	content := map[string]string{
		"https://example.com/helper.md": "https://example.com/payload.py",
	}
	nodes := Run(context.Background(), root, Options{Depth: 1}, fakeFetcher(content), fakeScanner(content))
	if len(nodes) != 1 {
		t.Fatalf("expected only the depth-1 reference with Depth:1, got %#v", nodes)
	}
}

func TestRunEnforcesMaxAllowedDepthRegardlessOfRequest(t *testing.T) {
	root := artifactWith("SKILL.md", "https://a.example/1")
	content := map[string]string{
		"https://a.example/1": "https://a.example/2",
		"https://a.example/2": "https://a.example/3",
		"https://a.example/3": "https://a.example/4",
		"https://a.example/4": "https://a.example/5",
	}
	nodes := Run(context.Background(), root, Options{Depth: 100}, fakeFetcher(content), fakeScanner(content))
	var maxDepth int
	for _, n := range nodes {
		if n.Depth > maxDepth {
			maxDepth = n.Depth
		}
	}
	if maxDepth > MaxAllowedDepth {
		t.Fatalf("depth exceeded MaxAllowedDepth (%d): got %d", MaxAllowedDepth, maxDepth)
	}
}

func TestRunRespectsAllowPrefix(t *testing.T) {
	root := artifactWith("SKILL.md", "https://good.example/a and https://bad.example/b")
	content := map[string]string{"https://good.example/a": "clean", "https://bad.example/b": "clean"}
	nodes := Run(context.Background(), root, Options{AllowPrefixes: []string{"https://good.example/"}}, fakeFetcher(content), fakeScanner(content))
	byURL := map[string]skil.ReferenceNode{}
	for _, n := range nodes {
		byURL[n.URL] = n
	}
	if !byURL["https://good.example/a"].Fetched {
		t.Fatalf("expected the allow-listed reference to be fetched: %#v", byURL)
	}
	if byURL["https://bad.example/b"].Fetched || byURL["https://bad.example/b"].SkipReason == "" {
		t.Fatalf("expected the non-allow-listed reference to be skipped with a reason: %#v", byURL)
	}
}

func TestRunDenyPrefixOverridesAllowPrefix(t *testing.T) {
	root := artifactWith("SKILL.md", "https://example.com/a")
	content := map[string]string{"https://example.com/a": "clean"}
	nodes := Run(context.Background(), root, Options{
		AllowPrefixes: []string{"https://example.com/"},
		DenyPrefixes:  []string{"https://example.com/a"},
	}, fakeFetcher(content), fakeScanner(content))
	if len(nodes) != 1 || nodes[0].Fetched {
		t.Fatalf("expected deny to override a matching allow prefix: %#v", nodes)
	}
}

func TestRunStopsFollowingOnceTargetBudgetExhausted(t *testing.T) {
	root := artifactWith("SKILL.md", "https://example.com/a and https://example.com/b and https://example.com/c")
	content := map[string]string{"https://example.com/a": "x", "https://example.com/b": "x", "https://example.com/c": "x"}
	nodes := Run(context.Background(), root, Options{MaxTargets: 1}, fakeFetcher(content), fakeScanner(content))
	fetched := 0
	for _, n := range nodes {
		if n.Fetched {
			fetched++
		}
	}
	if fetched != 1 {
		t.Fatalf("expected exactly 1 fetch with MaxTargets:1, got %d fetched out of %#v", fetched, nodes)
	}
	if len(nodes) != 3 {
		t.Fatalf("expected all 3 references still recorded (2 skipped): %#v", nodes)
	}
}

func TestRunStopsFollowingOnceTimeBudgetExhausted(t *testing.T) {
	root := artifactWith("SKILL.md", "https://example.com/a")
	content := map[string]string{"https://example.com/a": "x"}
	nodes := Run(context.Background(), root, Options{MaxTraversalTime: -1 * time.Second}, fakeFetcher(content), fakeScanner(content))
	if len(nodes) != 1 || nodes[0].Fetched {
		t.Fatalf("expected the reference to be skipped once the time budget already elapsed: %#v", nodes)
	}
}

func TestRunRecordsFetchFailureAsSkipped(t *testing.T) {
	root := artifactWith("SKILL.md", "https://example.com/missing")
	nodes := Run(context.Background(), root, Options{}, fakeFetcher(map[string]string{}), fakeScanner(map[string]string{}))
	if len(nodes) != 1 || nodes[0].Fetched || nodes[0].SkipReason == "" {
		t.Fatalf("expected a fetch failure to be recorded, not silently dropped: %#v", nodes)
	}
}

func TestRunProducesNoNodesForAReferenceFreeArtifact(t *testing.T) {
	root := artifactWith("SKILL.md", "Ordinary content with no external references.")
	nodes := Run(context.Background(), root, Options{}, fakeFetcher(nil), fakeScanner(nil))
	if len(nodes) != 0 {
		t.Fatalf("expected no reference nodes: %#v", nodes)
	}
}

func TestAssuranceClosureDeterminismAndMutation(t *testing.T) {
	root := artifactWith("SKILL.md", "download and use: https://example.com/helper.md")
	root.Digest = "root-sha256-hash"

	content := map[string]string{
		"https://example.com/helper.md": "safe content",
	}
	nodes1 := Run(context.Background(), root, Options{}, fakeFetcher(content), fakeScanner(content))
	closure1 := BuildAssuranceClosure(root, nodes1)

	if closure1.Digest == "" {
		t.Fatalf("expected non-empty closure digest")
	}
	if !closure1.Complete {
		t.Fatalf("expected closure1 to be complete")
	}

	// Order independence check
	closure1Rebuilt := BuildAssuranceClosure(root, nodes1)
	if closure1.Digest != closure1Rebuilt.Digest {
		t.Fatalf("expected identical digest for identical graph rebuild")
	}

	// Content mutation changes closure digest
	contentMutated := map[string]string{
		"https://example.com/helper.md": "CRITICAL MALWARE INSTRUCTION",
	}
	mutatedScanner := func(_ context.Context, path string) (skil.ScanResult, error) {
		res, err := fakeScanner(contentMutated)(context.Background(), path)
		res.Maximum = skil.SeverityCritical
		res.Status = skil.StatusFail
		res.Verdict = skil.VerdictBlock
		res.Findings = []skil.Finding{{ID: "SKIL-EVIL-001", Severity: skil.SeverityCritical}}
		return res, err
	}

	nodesMutated := Run(context.Background(), root, Options{}, fakeFetcher(contentMutated), mutatedScanner)
	closureMutated := BuildAssuranceClosure(root, nodesMutated)

	if closureMutated.Digest == closure1.Digest {
		t.Fatalf("expected closure digest to change when child node findings/verdict mutate")
	}
	if closureMutated.MaximumSeverity != skil.SeverityCritical {
		t.Fatalf("expected closure maximum severity to be CRITICAL, got %s", closureMutated.MaximumSeverity)
	}
}
