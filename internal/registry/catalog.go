package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type CatalogFilter struct {
	Namespace string
	Domain    string
	Query     string
}

type SearchResult struct {
	Entry        CatalogEntry `json:"entry"`
	Score        float64      `json:"score"`
	Relationship string       `json:"relationship,omitempty"`
}

type SkillCatalog interface {
	Add(ctx context.Context, entry CatalogEntry) error
	Remove(ctx context.Context, id string) error
	Update(ctx context.Context, entry CatalogEntry) error
	Get(ctx context.Context, id string) (*CatalogEntry, error)
	FindExact(ctx context.Context, fingerprint string) (*CatalogEntry, error)
	SearchSimilar(ctx context.Context, candidate CatalogEntry, topK int, provider SemanticSimilarityProvider) ([]SearchResult, error)
	List(ctx context.Context, filter CatalogFilter) ([]CatalogEntry, error)
	Save() error
}

type CatalogFileFormat struct {
	SchemaVersion         int            `json:"schema_version"`
	RepresentationVersion int            `json:"representation_version"`
	Skills                []CatalogEntry `json:"skills"`
}

type FileCatalog struct {
	mu       sync.RWMutex
	filePath string
	skills   map[string]CatalogEntry // ID -> CatalogEntry
}

func NewFileCatalog(path string) (*FileCatalog, error) {
	fc := &FileCatalog{
		filePath: path,
		skills:   make(map[string]CatalogEntry),
	}

	if path != "" {
		if err := fc.load(); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("load catalog file %s: %w", path, err)
		}
	}

	return fc, nil
}

func (fc *FileCatalog) load() error {
	data, err := os.ReadFile(fc.filePath)
	if err != nil {
		return err
	}

	var fmtCatalog CatalogFileFormat
	if err := json.Unmarshal(data, &fmtCatalog); err != nil {
		return err
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.skills = make(map[string]CatalogEntry, len(fmtCatalog.Skills))
	for _, entry := range fmtCatalog.Skills {
		fc.skills[entry.ID] = entry
	}

	return nil
}

func (fc *FileCatalog) Save() error {
	if fc.filePath == "" {
		return nil
	}

	fc.mu.RLock()
	var list []CatalogEntry
	for _, entry := range fc.skills {
		list = append(list, entry)
	}
	fc.mu.RUnlock()

	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})

	fmtCatalog := CatalogFileFormat{
		SchemaVersion:         1,
		RepresentationVersion: 1,
		Skills:                list,
	}

	data, err := json.MarshalIndent(fmtCatalog, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal catalog: %w", err)
	}

	dir := filepath.Dir(fc.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create catalog directory: %w", err)
		}
	}

	return os.WriteFile(fc.filePath, data, 0644)
}

func (fc *FileCatalog) Add(ctx context.Context, entry CatalogEntry) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if entry.ID == "" {
		entry.ID = entry.Metadata.Namespace + "/" + entry.Name
		if entry.Metadata.Namespace == "" {
			entry.ID = entry.Name
		}
	}

	fc.skills[entry.ID] = entry
	return nil
}

func (fc *FileCatalog) Remove(ctx context.Context, id string) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	delete(fc.skills, id)
	return nil
}

func (fc *FileCatalog) Update(ctx context.Context, entry CatalogEntry) error {
	return fc.Add(ctx, entry)
}

func (fc *FileCatalog) Get(ctx context.Context, id string) (*CatalogEntry, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	entry, ok := fc.skills[id]
	if !ok {
		return nil, fmt.Errorf("skill %s not found in catalog", id)
	}
	return &entry, nil
}

func (fc *FileCatalog) FindExact(ctx context.Context, fingerprint string) (*CatalogEntry, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	for _, entry := range fc.skills {
		if entry.Fingerprint.Value == fingerprint && fingerprint != "" {
			cp := entry
			return &cp, nil
		}
	}
	return nil, nil
}

func (fc *FileCatalog) SearchSimilar(ctx context.Context, candidate CatalogEntry, topK int, provider SemanticSimilarityProvider) ([]SearchResult, error) {
	fc.mu.RLock()
	entries := make([]CatalogEntry, 0, len(fc.skills))
	for _, e := range fc.skills {
		// Ignore candidate comparing to itself by ID
		if candidate.ID != "" && e.ID == candidate.ID {
			continue
		}
		// Multi-tenant scoping: if candidate specifies a namespace, non-empty matching or global is checked
		if candidate.Metadata.Namespace != "" && e.Metadata.Namespace != "" && e.Metadata.Namespace != candidate.Metadata.Namespace {
			continue
		}
		entries = append(entries, e)
	}
	fc.mu.RUnlock()

	if len(entries) == 0 {
		return nil, nil
	}

	if provider == nil {
		provider = NewLocalTFIDFProvider()
	}

	candVec := candidate.Embedding
	if len(candVec) == 0 {
		rep := BuildSemanticRepresentation(candidate.Metadata, candidate.Capabilities, "", RepresentationFull)
		vec, err := provider.Embed(ctx, rep)
		if err == nil {
			candVec = vec
		}
	}

	var results []SearchResult
	weights := DefaultCapabilityWeights()

	for _, e := range entries {
		nameSim := NameMetadataSimilarity(candidate.Metadata, e.Metadata).OverallScore
		capSim := CalculateCapabilityOverlap(candidate.Capabilities, e.Capabilities, weights).OverallScore

		var semSim float64
		if len(candVec) > 0 && len(e.Embedding) > 0 {
			semSim = provider.Similarity(candVec, e.Embedding)
		} else {
			eRep := BuildSemanticRepresentation(e.Metadata, e.Capabilities, "", RepresentationFull)
			eVec, err := provider.Embed(ctx, eRep)
			if err == nil {
				semSim = provider.Similarity(candVec, eVec)
			}
		}

		overallScore := (nameSim * 0.25) + (semSim * 0.40) + (capSim * 0.35)

		results = append(results, SearchResult{
			Entry: e,
			Score: overallScore,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if topK > 0 && len(results) > topK {
		results = results[:topK]
	}

	return results, nil
}

func (fc *FileCatalog) List(ctx context.Context, filter CatalogFilter) ([]CatalogEntry, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	var result []CatalogEntry
	qLower := strings.ToLower(filter.Query)

	for _, entry := range fc.skills {
		if filter.Namespace != "" && entry.Metadata.Namespace != filter.Namespace {
			continue
		}
		if filter.Domain != "" {
			domainMatch := false
			for _, d := range entry.Capabilities.Domain {
				if strings.EqualFold(d, filter.Domain) {
					domainMatch = true
					break
				}
			}
			if !domainMatch {
				continue
			}
		}
		if qLower != "" {
			haystack := strings.ToLower(entry.Name + " " + entry.Metadata.Title + " " + entry.Metadata.Description + " " + strings.Join(entry.Capabilities.Actions, " "))
			if !strings.Contains(haystack, qLower) {
				continue
			}
		}

		result = append(result, entry)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}
