package registry

import (
	"context"
	"fmt"
	"strings"
)

type LLMJudgeProvider interface {
	JudgeRelationship(ctx context.Context, cand Metadata, candCaps CapabilityFingerprint, candContent string, exist Metadata, existCaps CapabilityFingerprint, existContent string) (RelationshipType, float64, string, error)
}

type DuplicateAnalyzer struct {
	catalog   SkillCatalog
	provider  SemanticSimilarityProvider
	llmJudge  LLMJudgeProvider
	threshold ThresholdConfig
}

func NewDuplicateAnalyzer(catalog SkillCatalog, provider SemanticSimilarityProvider, judge LLMJudgeProvider, config AdmissionConfig) *DuplicateAnalyzer {
	if provider == nil {
		provider = NewLocalTFIDFProvider()
	}
	return &DuplicateAnalyzer{
		catalog:   catalog,
		provider:  provider,
		llmJudge:  judge,
		threshold: config.Thresholds,
	}
}

func (da *DuplicateAnalyzer) AnalyzeDuplicates(ctx context.Context, candidate CatalogEntry, candContent string, topK int) (DuplicateAnalysisResult, error) {
	result := DuplicateAnalysisResult{
		Candidate:      candidate.Metadata,
		Fingerprint:    candidate.Fingerprint,
		Capabilities:   candidate.Capabilities,
		Relationship:   RelationshipDistinct,
		Reason:         "No meaningful duplicate relationships found in catalog.",
		Recommendation: "Skill is distinct and ready for publishing.",
	}

	if da.catalog == nil {
		return result, nil
	}

	// Stage 1: Exact Duplicate Detection
	exactMatch, err := da.catalog.FindExact(ctx, candidate.Fingerprint.Value)
	if err != nil {
		return result, fmt.Errorf("exact match check: %w", err)
	}
	if exactMatch != nil && exactMatch.ID != candidate.ID {
		result.Relationship = RelationshipExactDuplicate
		result.Reason = fmt.Sprintf("Canonicalized skill content is 100%% identical to existing skill %q (SHA-256 %s).", exactMatch.Name, exactMatch.Fingerprint.Value)
		result.Recommendation = fmt.Sprintf("Do not publish exact duplicate. Use or update existing skill %q.", exactMatch.Name)
		result.Matches = append(result.Matches, DuplicateMatch{
			Entry:        *exactMatch,
			Relationship: RelationshipExactDuplicate,
			Scores: SimilarityScore{
				Name:       1.0,
				Semantic:   1.0,
				Capability: 1.0,
				Overall:    1.0,
			},
		})
		return result, nil
	}

	// Stage 2 & 3 & 4: Staged Catalog Search
	if topK <= 0 {
		topK = 5
	}
	similar, err := da.catalog.SearchSimilar(ctx, candidate, topK, da.provider)
	if err != nil {
		return result, fmt.Errorf("search similar skills: %w", err)
	}

	if len(similar) == 0 {
		return result, nil
	}

	weights := DefaultCapabilityWeights()
	candVec := candidate.Embedding
	if len(candVec) == 0 {
		candRep := BuildSemanticRepresentation(candidate.Metadata, candidate.Capabilities, candContent, RepresentationFull)
		candVec, _ = da.provider.Embed(ctx, candRep)
	}

	var matches []DuplicateMatch
	var topRelationship RelationshipType = RelationshipDistinct
	var topReason string
	var topRecommendation string

	for i, res := range similar {
		exist := res.Entry

		nameScore := NameMetadataSimilarity(candidate.Metadata, exist.Metadata).OverallScore
		capDetail := CalculateCapabilityOverlap(candidate.Capabilities, exist.Capabilities, weights)

		var semScore float64
		if len(candVec) > 0 && len(exist.Embedding) > 0 {
			semScore = da.provider.Similarity(candVec, exist.Embedding)
		} else {
			existRep := BuildSemanticRepresentation(exist.Metadata, exist.Capabilities, "", RepresentationFull)
			existVec, _ := da.provider.Embed(ctx, existRep)
			semScore = da.provider.Similarity(candVec, existVec)
		}

		overall := (nameScore * 0.20) + (semScore * 0.40) + (capDetail.OverallScore * 0.40)

		rel, reason, rec := da.classifyRelationship(candidate, exist, nameScore, semScore, capDetail)

		// Optional LLM Judge for top match
		if i == 0 && da.llmJudge != nil && (rel == RelationshipSemanticDuplicate || rel == RelationshipHighSimilarity || rel == RelationshipSubset || rel == RelationshipSuperset) {
			llmRel, llmConf, llmReason, err := da.llmJudge.JudgeRelationship(ctx, candidate.Metadata, candidate.Capabilities, candContent, exist.Metadata, exist.Capabilities, "")
			if err == nil && llmConf >= 0.80 {
				rel = llmRel
				reason = fmt.Sprintf("LLM Judge (%d%% confidence): %s", int(llmConf*100), llmReason)
			}
		}

		match := DuplicateMatch{
			Entry:        exist,
			Relationship: rel,
			Scores: SimilarityScore{
				Name:       nameScore,
				Semantic:   semScore,
				Capability: capDetail.OverallScore,
				Overall:    overall,
			},
			CapabilityDetail: capDetail,
		}
		matches = append(matches, match)

		if i == 0 {
			topRelationship = rel
			topReason = reason
			topRecommendation = rec
		}
	}

	result.Relationship = topRelationship
	result.Reason = topReason
	result.Recommendation = topRecommendation
	result.Matches = matches

	return result, nil
}

func (da *DuplicateAnalyzer) classifyRelationship(cand, exist CatalogEntry, nameScore, semScore float64, capDetail CapabilityOverlapResult) (RelationshipType, string, string) {
	// Exact digest check
	if cand.Fingerprint.Value != "" && cand.Fingerprint.Value == exist.Fingerprint.Value {
		return RelationshipExactDuplicate,
			fmt.Sprintf("Canonicalized skill digest matches %q exactly.", exist.Name),
			fmt.Sprintf("Use existing skill %q instead of publishing a duplicate.", exist.Name)
	}

	candSubExist, existSubCand := DirectionalContainment(cand.Capabilities.Actions, exist.Capabilities.Actions)
	toolCandSub, toolExistSub := DirectionalContainment(cand.Capabilities.Tools, exist.Capabilities.Tools)

	// Check for SUBSET (Candidate is subset of existing skill)
	if candSubExist >= da.threshold.CapabilitySubset && toolCandSub >= da.threshold.CapabilitySubset && (existSubCand < 0.90 || toolExistSub < 0.90) {
		return RelationshipSubset,
			fmt.Sprintf("Candidate provides a strict subset of actions and tools provided by existing skill %q.", exist.Name),
			fmt.Sprintf("Consider using or extending existing skill %q.", exist.Name)
	}

	// Check for SUPERSET (Candidate extends existing skill)
	if existSubCand >= da.threshold.CapabilitySuperset && toolExistSub >= da.threshold.CapabilitySuperset && (candSubExist < 0.90 || toolCandSub < 0.90) {
		return RelationshipSuperset,
			fmt.Sprintf("Candidate significantly extends existing skill %q with %d unique capabilities.", exist.Name, len(capDetail.UniqueCapabilities)),
			fmt.Sprintf("Consider integrating extensions into %q or publishing as specialized extension.", exist.Name)
	}

	// Semantic Duplicate
	if semScore >= da.threshold.SemanticDuplicate && capDetail.OverallScore >= da.threshold.CapabilityDuplicate {
		return RelationshipSemanticDuplicate,
			fmt.Sprintf("Candidate is semantically equivalent (%d%% similarity, %d%% capability overlap) to existing skill %q.", int(semScore*100), int(capDetail.OverallScore*100), exist.Name),
			fmt.Sprintf("Extend or contribute to existing skill %q instead of creating a parallel implementation.", exist.Name)
	}

	// High Similarity
	if semScore >= da.threshold.SemanticHighSimilarity || (nameScore >= 0.85 && capDetail.OverallScore >= 0.80) {
		return RelationshipHighSimilarity,
			fmt.Sprintf("Candidate has high overlap (%d%% semantic, %d%% capability) with existing skill %q.", int(semScore*100), int(capDetail.OverallScore*100), exist.Name),
			fmt.Sprintf("Review candidate for potential redundancy with %q.", exist.Name)
	}

	// Capability Overlap
	if capDetail.OverallScore >= 0.70 {
		return RelationshipCapabilityOverlap,
			fmt.Sprintf("Candidate shares significant functional capabilities (%d%% overlap) with %q.", int(capDetail.OverallScore*100), exist.Name),
			fmt.Sprintf("Verify that candidate is sufficiently distinct from %q.", exist.Name)
	}

	// Complementary (same domain, different actions/tools)
	if isDomainShared(cand.Capabilities.Domain, exist.Capabilities.Domain) && semScore >= da.threshold.SemanticRelated && capDetail.OverallScore < 0.70 {
		return RelationshipComplementary,
			fmt.Sprintf("Candidate belongs to domain %q alongside %q, but performs complementary tasks.", strings.Join(cand.Capabilities.Domain, ", "), exist.Name),
			"Publish candidate as a complementary specialized skill."
	}

	// Related
	if semScore >= da.threshold.SemanticRelated {
		return RelationshipRelated,
			fmt.Sprintf("Candidate is related (%d%% similarity) to %q.", int(semScore*100), exist.Name),
			"Skill is distinct enough for admission."
	}

	return RelationshipDistinct,
		"No meaningful duplicate relationship detected.",
		"Skill is distinct and ready for publishing."
}

func isDomainShared(a, b []string) bool {
	bMap := make(map[string]bool, len(b))
	for _, d := range b {
		bMap[d] = true
	}
	for _, d := range a {
		if bMap[d] {
			return true
		}
	}
	return false
}
