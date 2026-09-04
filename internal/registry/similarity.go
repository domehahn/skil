package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type RepresentationMode string

const (
	RepresentationMetadata     RepresentationMode = "metadata"
	RepresentationInstructions RepresentationMode = "instructions"
	RepresentationCapabilities RepresentationMode = "capabilities"
	RepresentationFull         RepresentationMode = "full"
)

type NameSimilarityResult struct {
	Levenshtein  float64 `json:"levenshtein"`
	JaroWinkler  float64 `json:"jaro_winkler"`
	TokenSet     float64 `json:"token_set"`
	OverallScore float64 `json:"overall_score"`
}

func NameMetadataSimilarity(cand, exist Metadata) NameSimilarityResult {
	candSlug := normalizeSlug(cand.Name)
	existSlug := normalizeSlug(exist.Name)

	lev := normalizedLevenshtein(candSlug, existSlug)
	jw := jaroWinkler(candSlug, existSlug)
	tokenRatio := tokenSetRatio(candSlug, existSlug)

	titleScore := jaroWinkler(strings.ToLower(cand.Title), strings.ToLower(exist.Title))
	if cand.Title == "" || exist.Title == "" {
		titleScore = jw
	}

	overall := (lev * 0.3) + (jw * 0.4) + (tokenRatio * 0.2) + (titleScore * 0.1)

	return NameSimilarityResult{
		Levenshtein:  lev,
		JaroWinkler:  jw,
		TokenSet:     tokenRatio,
		OverallScore: overall,
	}
}

type SemanticSimilarityProvider interface {
	Name() string
	Embed(ctx context.Context, input string) ([]float32, error)
	Similarity(a, b []float32) float64
}

// LocalTFIDFProvider provides 100% offline semantic similarity using character/word n-gram TF-IDF embeddings.
type LocalTFIDFProvider struct{}

func NewLocalTFIDFProvider() *LocalTFIDFProvider {
	return &LocalTFIDFProvider{}
}

func (p *LocalTFIDFProvider) Name() string {
	return "local-tfidf"
}

func (p *LocalTFIDFProvider) Embed(ctx context.Context, input string) ([]float32, error) {
	tokens := tokenize(input)
	if len(tokens) == 0 {
		return make([]float32, 128), nil
	}

	vector := make([]float32, 128)
	for _, tok := range tokens {
		h := fnv1aHash(tok)
		idx := h % 128
		vector[idx] += 1.0
	}

	// L2 Normalize
	var sumSq float64
	for _, v := range vector {
		sumSq += float64(v * v)
	}
	if sumSq > 0 {
		norm := float32(math.Sqrt(sumSq))
		for i := range vector {
			vector[i] /= norm
		}
	}
	return vector, nil
}

func (p *LocalTFIDFProvider) Similarity(a, b []float32) float64 {
	return CosineSimilarity(a, b)
}

func CosineSimilarity(a, b []float32) float64 {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return 0.0
	}
	var dot, normA, normB float64
	for i := range a {
		valA := float64(a[i])
		valB := float64(b[i])
		dot += valA * valB
		normA += valA * valA
		normB += valB * valB
	}
	if normA == 0 || normB == 0 {
		return 0.0
	}
	sim := dot / (math.Sqrt(normA) * math.Sqrt(normB))
	if sim < 0 {
		return 0
	}
	if sim > 1 {
		return 1
	}
	return sim
}

// ExternalProviderAdapter attempts external SaaS embedding with fallback to local provider.
type ExternalProviderAdapter struct {
	providerName string
	endpoint     string
	apiKeyEnv    string
	local        *LocalTFIDFProvider
	client       *http.Client
}

func NewExternalProviderAdapter(name, endpoint, apiKeyEnv string) *ExternalProviderAdapter {
	return &ExternalProviderAdapter{
		providerName: name,
		endpoint:     endpoint,
		apiKeyEnv:    apiKeyEnv,
		local:        NewLocalTFIDFProvider(),
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

func (e *ExternalProviderAdapter) Name() string {
	return e.providerName
}

func (e *ExternalProviderAdapter) Embed(ctx context.Context, input string) ([]float32, error) {
	key := os.Getenv(e.apiKeyEnv)
	if key == "" || e.endpoint == "" {
		return e.local.Embed(ctx, input)
	}

	payload := map[string]interface{}{
		"input": input,
		"model": "text-embedding-3-small",
	}
	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return e.local.Embed(ctx, input)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := e.client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return e.local.Embed(ctx, input)
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || len(result.Data) == 0 {
		return e.local.Embed(ctx, input)
	}

	return result.Data[0].Embedding, nil
}

func (e *ExternalProviderAdapter) Similarity(a, b []float32) float64 {
	return CosineSimilarity(a, b)
}

type EmbeddingCache struct {
	mu    sync.RWMutex
	cache map[string][]float32
}

func NewEmbeddingCache() *EmbeddingCache {
	return &EmbeddingCache{
		cache: make(map[string][]float32),
	}
}

func (c *EmbeddingCache) GetKey(skillFingerprint, providerName, modelName string, repMode RepresentationMode) string {
	h := sha256.New()
	h.Write([]byte(skillFingerprint + "|" + providerName + "|" + modelName + "|" + string(repMode)))
	return hex.EncodeToString(h.Sum(nil))
}

func (c *EmbeddingCache) Get(key string) ([]float32, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	vec, ok := c.cache[key]
	return vec, ok
}

func (c *EmbeddingCache) Set(key string, vec []float32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = vec
}

func BuildSemanticRepresentation(meta Metadata, caps CapabilityFingerprint, content string, mode RepresentationMode) string {
	var b strings.Builder

	b.WriteString("NAME: " + meta.Name + "\n")
	if meta.Title != "" {
		b.WriteString("TITLE: " + meta.Title + "\n")
	}
	if meta.Description != "" {
		b.WriteString("DESCRIPTION: " + meta.Description + "\n")
	}

	if mode == RepresentationMetadata {
		return b.String()
	}

	if len(caps.Domain) > 0 {
		b.WriteString("DOMAIN: " + strings.Join(caps.Domain, ", ") + "\n")
	}
	if len(caps.Actions) > 0 {
		b.WriteString("ACTIONS: " + strings.Join(caps.Actions, ", ") + "\n")
	}
	if len(caps.Tools) > 0 {
		b.WriteString("TOOLS: " + strings.Join(caps.Tools, ", ") + "\n")
	}
	if len(caps.Resources) > 0 {
		b.WriteString("RESOURCES: " + strings.Join(caps.Resources, ", ") + "\n")
	}

	if mode == RepresentationCapabilities {
		return b.String()
	}

	if mode == RepresentationFull && content != "" {
		b.WriteString("INSTRUCTIONS:\n" + truncateContent(content, 2000) + "\n")
	}

	return b.String()
}

func truncateContent(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}

func normalizeSlug(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	lower = strings.ReplaceAll(lower, "k8s", "kubernetes")
	lower = strings.ReplaceAll(lower, "_", "-")
	return lower
}

func normalizedLevenshtein(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	dist := levenshteinDistance(a, b)
	maxLen := math.Max(float64(len(a)), float64(len(b)))
	return 1.0 - (float64(dist) / maxLen)
}

func levenshteinDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)

	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 1; j <= lb; j++ {
		d[0][j] = j
	}

	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = minInt(
				d[i-1][j]+1,
				d[i][j-1]+1,
				d[i-1][j-1]+cost,
			)
		}
	}
	return d[la][lb]
}

func jaroWinkler(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	r1, r2 := []rune(s1), []rune(s2)
	l1, l2 := len(r1), len(r2)
	if l1 == 0 || l2 == 0 {
		return 0.0
	}

	matchDistance := maxInt(l1, l2)/2 - 1
	if matchDistance < 0 {
		matchDistance = 0
	}

	s1Matches := make([]bool, l1)
	s2Matches := make([]bool, l2)

	matches := 0
	transpositions := 0

	for i := 0; i < l1; i++ {
		start := maxInt(0, i-matchDistance)
		end := minInt(i+matchDistance+1, l2)

		for j := start; j < end; j++ {
			if s2Matches[j] || r1[i] != r2[j] {
				continue
			}
			s1Matches[i] = true
			s2Matches[j] = true
			matches++
			break
		}
	}

	if matches == 0 {
		return 0.0
	}

	k := 0
	for i := 0; i < l1; i++ {
		if !s1Matches[i] {
			continue
		}
		for !s2Matches[k] {
			k++
		}
		if r1[i] != r2[k] {
			transpositions++
		}
		k++
	}

	m := float64(matches)
	jaro := (m/float64(l1) + m/float64(l2) + (m-float64(transpositions/2))/m) / 3.0

	// Winkler prefix adjustment
	prefix := 0
	for i := 0; i < minInt(4, minInt(l1, l2)); i++ {
		if r1[i] == r2[i] {
			prefix++
		} else {
			break
		}
	}

	return jaro + float64(prefix)*0.1*(1.0-jaro)
}

func tokenSetRatio(s1, s2 string) float64 {
	t1 := tokenizeSet(s1)
	t2 := tokenizeSet(s2)

	if len(t1) == 0 && len(t2) == 0 {
		return 1.0
	}
	if len(t1) == 0 || len(t2) == 0 {
		return 0.0
	}

	intersection := 0
	for t := range t1 {
		if t2[t] {
			intersection++
		}
	}

	union := len(t1) + len(t2) - intersection
	if union == 0 {
		return 0.0
	}
	return float64(intersection) / float64(union)
}

func tokenizeSet(s string) map[string]bool {
	tokens := tokenize(s)
	m := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		if t != "" {
			m[t] = true
		}
	}
	return m
}

func tokenize(s string) []string {
	clean := strings.ToLower(s)
	var tokens []string
	var current strings.Builder
	for _, r := range clean {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			current.WriteRune(r)
		} else {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

func fnv1aHash(s string) uint32 {
	var hash uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= 16777619
	}
	return hash
}

func minInt(a, b int, rest ...int) int {
	m := a
	if b < m {
		m = b
	}
	for _, v := range rest {
		if v < m {
			m = v
		}
	}
	return m
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
