package contextefficiency

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// EfficiencyReport details prompt token efficiency and context redundancy metrics.
type EfficiencyReport struct {
	TotalTokens             int      `json:"total_tokens" yaml:"total_tokens"`
	InstructionTokens       int      `json:"instruction_tokens" yaml:"instruction_tokens"`
	RedundantTokens         int      `json:"redundant_tokens" yaml:"redundant_tokens"`
	PotentialSavingsPercent float64  `json:"potential_savings_percent" yaml:"potential_savings_percent"`
	RepeatedConcepts        []string `json:"repeated_concepts,omitempty" yaml:"repeated_concepts,omitempty"`
	Recommendations         []string `json:"recommendations,omitempty" yaml:"recommendations,omitempty"`
}

// AnalyzeEfficiency evaluates prompt token usage and detects intra-skill prompt redundancy.
func AnalyzeEfficiency(art *skil.Artifact) *EfficiencyReport {
	if art == nil || len(art.Files) == 0 {
		return &EfficiencyReport{}
	}

	var totalWords int
	var instructionWords int
	phraseCounts := make(map[string]int)

	for _, file := range art.Files {
		ext := strings.ToLower(filepath.Ext(file.Path))
		isText := ext == ".md" || ext == ".txt" || ext == ".yaml" || ext == ".yml" || filepath.Base(file.Path) == "SKILL.md"

		if !isText {
			continue
		}

		text := string(file.Data)
		words := strings.Fields(text)
		wordCount := len(words)
		totalWords += wordCount

		if filepath.Base(file.Path) == "SKILL.md" {
			instructionWords += wordCount
		}

		// N-gram phrase repetition analysis (3-word to 5-word phrases)
		normalizedWords := make([]string, len(words))
		for i, w := range words {
			normalizedWords[i] = strings.ToLower(strings.Trim(w, ".,;:!?()[]{}\"'`#*-"))
		}

		for n := 3; n <= 5; n++ {
			for i := 0; i <= len(normalizedWords)-n; i++ {
				phrase := strings.Join(normalizedWords[i:i+n], " ")
				if len(phrase) < 12 {
					continue
				}
				// Skip markdown/code noise
				if strings.Contains(phrase, "```") || strings.Contains(phrase, "---") {
					continue
				}
				phraseCounts[phrase]++
			}
		}
	}

	// Calculate redundant tokens from phrases repeated >= 3 times
	redundantWords := 0
	type conceptPair struct {
		phrase string
		count  int
	}
	var repeated []conceptPair

	for phrase, count := range phraseCounts {
		if count >= 3 {
			wordsInPhrase := len(strings.Fields(phrase))
			// Only count extra repetitions beyond the first occurrence
			redundantWords += (count - 1) * wordsInPhrase
			repeated = append(repeated, conceptPair{phrase: phrase, count: count})
		}
	}

	sort.Slice(repeated, func(i, j int) bool {
		return repeated[i].count > repeated[j].count
	})

	var topRepeated []string
	seen := make(map[string]bool)
	for _, p := range repeated {
		if len(topRepeated) >= 5 {
			break
		}
		// Deduplicate sub-phrases
		isSub := false
		for _, existing := range topRepeated {
			if strings.Contains(existing, p.phrase) {
				isSub = true
				break
			}
		}
		if !isSub && !seen[p.phrase] {
			topRepeated = append(topRepeated, fmt.Sprintf("%s (x%d)", p.phrase, p.count))
			seen[p.phrase] = true
		}
	}

	// Approximate 1 word ≈ 1.33 LLM tokens
	totalTokens := int(float64(totalWords) * 1.33)
	instTokens := int(float64(instructionWords) * 1.33)
	redundantTokens := int(float64(redundantWords) * 1.33)

	if redundantTokens > totalTokens {
		redundantTokens = totalTokens / 4
	}

	savingsPercent := 0.0
	if totalTokens > 0 {
		savingsPercent = (float64(redundantTokens) / float64(totalTokens)) * 100.0
	}

	var recommendations []string
	if savingsPercent > 10.0 {
		recommendations = append(recommendations, fmt.Sprintf("Consolidate repeated prompt concepts to save up to %.1f%% context capacity.", savingsPercent))
	} else {
		recommendations = append(recommendations, "Prompt context efficiency is optimal.")
	}

	return &EfficiencyReport{
		TotalTokens:             totalTokens,
		InstructionTokens:       instTokens,
		RedundantTokens:         redundantTokens,
		PotentialSavingsPercent: float64(int(savingsPercent*10.0)) / 10.0,
		RepeatedConcepts:        topRepeated,
		Recommendations:         recommendations,
	}
}
