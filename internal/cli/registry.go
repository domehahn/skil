package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/domehahn/skil/internal/registry"
	"gopkg.in/yaml.v3"
)

const (
	ExitAdmissionReject = 2
	ExitAdmissionReview = 3
)

func (a *App) registryCommand(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("registry requires a subcommand: check, index, update, list, search, similar, or compare"))
	}

	switch args[0] {
	case "check":
		return a.registryCheck(ctx, args[1:])
	case "index":
		return a.registryIndex(ctx, args[1:])
	case "update":
		return a.registryIndex(ctx, args[1:])
	case "list":
		return a.registryList(ctx, args[1:])
	case "search":
		return a.registrySearch(ctx, args[1:])
	case "similar":
		return a.registrySimilar(ctx, args[1:])
	case "compare":
		return a.registryCompare(ctx, args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown registry subcommand %q", args[0]))
	}
}

func (a *App) registryCheck(ctx context.Context, args []string) int {
	fs := newFlags("registry check", a.Err)
	catalogPath := fs.String("catalog", ".skil/catalog.json", "path to skill catalog index JSON file")
	namespace := fs.String("namespace", "", "namespace scope")
	format := fs.String("format", "terminal", "output format: terminal, json, sarif")
	failOn := fs.String("fail-on", "reject", "fail policy trigger: reject, review, duplicate")
	policyPath := fs.String("policy", "", "custom admission policy YAML file")

	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	skillPath := fs.Arg(0)
	candEntry, candContent, err := registry.LoadCandidateEntry(skillPath, *namespace)
	if err != nil {
		return a.inputError(fmt.Errorf("load candidate skill %s: %w", skillPath, err))
	}

	cat, err := registry.NewFileCatalog(*catalogPath)
	if err != nil {
		return a.inputError(fmt.Errorf("open catalog %s: %w", *catalogPath, err))
	}

	config := registry.DefaultAdmissionConfig()
	if *policyPath != "" {
		data, err := os.ReadFile(*policyPath)
		if err == nil {
			_ = yaml.Unmarshal(data, &config)
		}
	}

	provider := registry.NewLocalTFIDFProvider()
	analyzer := registry.NewDuplicateAnalyzer(cat, provider, nil, config)
	evaluator := registry.NewAdmissionEvaluator(config)

	dupAnalysis, err := analyzer.AnalyzeDuplicates(ctx, candEntry, candContent, 5)
	if err != nil {
		return a.inputError(fmt.Errorf("analyze duplicates: %w", err))
	}

	admissionResult := evaluator.EvaluateAdmission(ctx, dupAnalysis)

	switch *format {
	case "json":
		data, _ := json.MarshalIndent(admissionResult, "", "  ")
		fmt.Fprintln(a.Out, string(data))
	case "sarif":
		sarifBytes, err := registry.GenerateSARIFReport(admissionResult, "skil-registry.sarif")
		if err != nil {
			return a.inputError(err)
		}
		fmt.Fprintln(a.Out, string(sarifBytes))
	default:
		a.printTerminalAdmission(admissionResult)
	}

	// Exit code enforcement
	switch strings.ToLower(*failOn) {
	case "reject":
		if admissionResult.Decision == registry.DecisionReject {
			return ExitAdmissionReject
		}
	case "review":
		if admissionResult.Decision == registry.DecisionReject {
			return ExitAdmissionReject
		}
		if admissionResult.Decision == registry.DecisionReview {
			return ExitAdmissionReview
		}
	case "duplicate":
		if admissionResult.Relationship == registry.RelationshipExactDuplicate || admissionResult.Relationship == registry.RelationshipSemanticDuplicate {
			return ExitAdmissionReject
		}
	}

	return ExitOK
}

func (a *App) registryIndex(ctx context.Context, args []string) int {
	fs := newFlags("registry index", a.Err)
	catalogPath := fs.String("catalog", ".skil/catalog.json", "path to skill catalog index JSON file")
	namespace := fs.String("namespace", "", "namespace scope")

	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	targetDir := fs.Arg(0)
	cat, err := registry.NewFileCatalog(*catalogPath)
	if err != nil {
		return a.inputError(fmt.Errorf("open catalog %s: %w", *catalogPath, err))
	}

	provider := registry.NewLocalTFIDFProvider()
	indexedCount := 0

	entries, err := os.ReadDir(targetDir)
	if err != nil {
		// Single skill directory fallback
		entry, candContent, err := registry.LoadCandidateEntry(targetDir, *namespace)
		if err == nil {
			rep := registry.BuildSemanticRepresentation(entry.Metadata, entry.Capabilities, candContent, registry.RepresentationFull)
			vec, _ := provider.Embed(ctx, rep)
			entry.Embedding = vec
			_ = cat.Add(ctx, entry)
			indexedCount = 1
		}
	} else {
		for _, e := range entries {
			if !e.IsDir() && e.Name() != "SKILL.md" && e.Name() != "skil.yaml" {
				continue
			}
			skillSubDir := filepath.Join(targetDir, e.Name())
			if !e.IsDir() {
				skillSubDir = targetDir
			}

			entry, candContent, err := registry.LoadCandidateEntry(skillSubDir, *namespace)
			if err != nil {
				continue
			}

			rep := registry.BuildSemanticRepresentation(entry.Metadata, entry.Capabilities, candContent, registry.RepresentationFull)
			vec, _ := provider.Embed(ctx, rep)
			entry.Embedding = vec

			if err := cat.Add(ctx, entry); err == nil {
				indexedCount++
			}
			if !e.IsDir() {
				break
			}
		}
	}

	if err := cat.Save(); err != nil {
		return a.inputError(fmt.Errorf("save catalog: %w", err))
	}

	fmt.Fprintf(a.Out, "Successfully indexed %d skill(s) into catalog %s\n", indexedCount, *catalogPath)
	return ExitOK
}

func (a *App) registryList(ctx context.Context, args []string) int {
	fs := newFlags("registry list", a.Err)
	catalogPath := fs.String("catalog", ".skil/catalog.json", "path to catalog JSON file")
	namespace := fs.String("namespace", "", "namespace filter")
	domain := fs.String("domain", "", "domain filter")
	format := fs.String("format", "terminal", "output format: terminal, json")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	cat, err := registry.NewFileCatalog(*catalogPath)
	if err != nil {
		return a.inputError(fmt.Errorf("open catalog %s: %w", *catalogPath, err))
	}

	list, err := cat.List(ctx, registry.CatalogFilter{Namespace: *namespace, Domain: *domain})
	if err != nil {
		return a.inputError(err)
	}

	if *format == "json" {
		data, _ := json.MarshalIndent(list, "", "  ")
		fmt.Fprintln(a.Out, string(data))
		return ExitOK
	}

	fmt.Fprintf(a.Out, "SKIL Registry Catalog (%s)\n", *catalogPath)
	fmt.Fprintln(a.Out, strings.Repeat("─", 60))
	if len(list) == 0 {
		fmt.Fprintln(a.Out, "No skills indexed in catalog.")
		return ExitOK
	}

	for _, entry := range list {
		fmt.Fprintf(a.Out, "  %-30s  v%-8s  [%s]\n", entry.Name, entry.Version, strings.Join(entry.Capabilities.Domain, ", "))
		if entry.Metadata.Description != "" {
			fmt.Fprintf(a.Out, "    %s\n", truncateStr(entry.Metadata.Description, 70))
		}
	}
	return ExitOK
}

func (a *App) registrySearch(ctx context.Context, args []string) int {
	fs := newFlags("registry search", a.Err)
	catalogPath := fs.String("catalog", ".skil/catalog.json", "path to catalog JSON file")
	topK := fs.Int("top-k", 5, "maximum number of results")

	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	query := fs.Arg(0)
	cat, err := registry.NewFileCatalog(*catalogPath)
	if err != nil {
		return a.inputError(fmt.Errorf("open catalog %s: %w", *catalogPath, err))
	}

	provider := registry.NewLocalTFIDFProvider()
	dummyCand := registry.CatalogEntry{
		Metadata: registry.Metadata{Name: "query", Description: query},
	}

	results, err := cat.SearchSimilar(ctx, dummyCand, *topK, provider)
	if err != nil {
		return a.inputError(err)
	}

	fmt.Fprintf(a.Out, "SKIL Registry Search Results for %q\n", query)
	fmt.Fprintln(a.Out, strings.Repeat("─", 60))

	if len(results) == 0 {
		fmt.Fprintln(a.Out, "No matching skills found.")
		return ExitOK
	}

	for _, res := range results {
		fmt.Fprintf(a.Out, "  %3d%%  %-30s  v%-8s\n", int(res.Score*100), res.Entry.Name, res.Entry.Version)
		if res.Entry.Metadata.Description != "" {
			fmt.Fprintf(a.Out, "       %s\n", truncateStr(res.Entry.Metadata.Description, 70))
		}
	}
	return ExitOK
}

func (a *App) registrySimilar(ctx context.Context, args []string) int {
	fs := newFlags("registry similar", a.Err)
	catalogPath := fs.String("catalog", ".skil/catalog.json", "path to catalog JSON file")
	topK := fs.Int("top-k", 5, "maximum number of similar skills")

	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	skillPath := fs.Arg(0)
	candEntry, candContent, err := registry.LoadCandidateEntry(skillPath, "")
	if err != nil {
		return a.inputError(err)
	}

	cat, err := registry.NewFileCatalog(*catalogPath)
	if err != nil {
		return a.inputError(err)
	}

	provider := registry.NewLocalTFIDFProvider()
	rep := registry.BuildSemanticRepresentation(candEntry.Metadata, candEntry.Capabilities, candContent, registry.RepresentationFull)
	vec, _ := provider.Embed(ctx, rep)
	candEntry.Embedding = vec

	results, err := cat.SearchSimilar(ctx, candEntry, *topK, provider)
	if err != nil {
		return a.inputError(err)
	}

	fmt.Fprintf(a.Out, "Skills Similar to %q\n", candEntry.Name)
	fmt.Fprintln(a.Out, strings.Repeat("─", 60))

	if len(results) == 0 {
		fmt.Fprintln(a.Out, "No similar skills found.")
		return ExitOK
	}

	for _, res := range results {
		fmt.Fprintf(a.Out, "  %3d%%  %-30s  v%-8s\n", int(res.Score*100), res.Entry.Name, res.Entry.Version)
	}
	return ExitOK
}

func (a *App) registryCompare(ctx context.Context, args []string) int {
	fs := newFlags("registry compare", a.Err)
	catalogPath := fs.String("catalog", ".skil/catalog.json", "path to catalog JSON file")

	if code := parse(fs, args, 2); code != ExitOK {
		return code
	}

	candPath := fs.Arg(0)
	existTarget := fs.Arg(1)

	candEntry, candContent, err := registry.LoadCandidateEntry(candPath, "")
	if err != nil {
		return a.inputError(fmt.Errorf("load candidate %s: %w", candPath, err))
	}

	var existEntry registry.CatalogEntry
	cat, err := registry.NewFileCatalog(*catalogPath)
	if err == nil {
		if found, _ := cat.Get(ctx, existTarget); found != nil {
			existEntry = *found
		}
	}
	if existEntry.Name == "" {
		loaded, _, err := registry.LoadCandidateEntry(existTarget, "")
		if err != nil {
			return a.inputError(fmt.Errorf("load target skill %s: %w", existTarget, err))
		}
		existEntry = loaded
	}

	weights := registry.DefaultCapabilityWeights()
	capOverlap := registry.CalculateCapabilityOverlap(candEntry.Capabilities, existEntry.Capabilities, weights)
	nameSim := registry.NameMetadataSimilarity(candEntry.Metadata, existEntry.Metadata).OverallScore

	provider := registry.NewLocalTFIDFProvider()
	candRep := registry.BuildSemanticRepresentation(candEntry.Metadata, candEntry.Capabilities, candContent, registry.RepresentationFull)
	candVec, _ := provider.Embed(ctx, candRep)
	existRep := registry.BuildSemanticRepresentation(existEntry.Metadata, existEntry.Capabilities, "", registry.RepresentationFull)
	existVec, _ := provider.Embed(ctx, existRep)
	semSim := provider.Similarity(candVec, existVec)

	fmt.Fprintf(a.Out, "SKIL Registry Skill Comparison\n")
	fmt.Fprintln(a.Out, strings.Repeat("─", 60))
	fmt.Fprintf(a.Out, "Candidate: %s\nExisting:  %s\n\n", candEntry.Name, existEntry.Name)

	fmt.Fprintf(a.Out, "Similarity Scores:\n")
	fmt.Fprintf(a.Out, "  Semantic:    %3d%%\n", int(semSim*100))
	fmt.Fprintf(a.Out, "  Capability:  %3d%%\n", int(capOverlap.OverallScore*100))
	fmt.Fprintf(a.Out, "  Name:        %3d%%\n\n", int(nameSim*100))

	fmt.Fprintf(a.Out, "Overlapping Capabilities:\n")
	if len(capOverlap.OverlappingCapabilities) == 0 {
		fmt.Fprintln(a.Out, "  (none)")
	} else {
		for _, cap := range capOverlap.OverlappingCapabilities {
			fmt.Fprintf(a.Out, "  ✓ %s\n", cap)
		}
	}

	fmt.Fprintf(a.Out, "\nUnique Candidate Capabilities:\n")
	if len(capOverlap.UniqueCapabilities) == 0 {
		fmt.Fprintln(a.Out, "  (none)")
	} else {
		for _, cap := range capOverlap.UniqueCapabilities {
			fmt.Fprintf(a.Out, "  + %s\n", cap)
		}
	}

	return ExitOK
}

func (a *App) printTerminalAdmission(res registry.AdmissionResult) {
	fmt.Fprintf(a.Out, "SKIL Registry Admission Check\n")
	fmt.Fprintln(a.Out, strings.Repeat("─", 60))
	fmt.Fprintf(a.Out, "Candidate:    %s\n", res.Candidate)
	if res.MostSimilarSkill != "" {
		fmt.Fprintf(a.Out, "Most Similar: %s\n", res.MostSimilarSkill)
	}
	fmt.Fprintf(a.Out, "Relationship: %s\n", res.Relationship)
	fmt.Fprintf(a.Out, "Decision:     %s\n\n", res.Decision)

	if res.MostSimilarSkill != "" {
		fmt.Fprintf(a.Out, "Similarity Breakdown:\n")
		fmt.Fprintf(a.Out, "  Semantic:    %3d%%\n", int(res.Scores.Semantic*100))
		fmt.Fprintf(a.Out, "  Capability:  %3d%%\n", int(res.Scores.Capability*100))
		fmt.Fprintf(a.Out, "  Name:        %3d%%\n\n", int(res.Scores.Name*100))
	}

	fmt.Fprintf(a.Out, "Reason:\n  %s\n\n", res.Reason)
	fmt.Fprintf(a.Out, "Recommendation:\n  %s\n", res.Recommendation)
}
func truncateStr(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
