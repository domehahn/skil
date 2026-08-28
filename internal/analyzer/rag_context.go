package analyzer

import (
	"bufio"
	"context"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

const (
	RuleRAGProvenanceMissing  = "SKIL-RAG-001"
	RuleRAGBoundaryConfusion  = "SKIL-RAG-002"
	RuleRAGRetrievalExecFlow  = "SKIL-RAG-003"
)

type RAGContext struct{}

func NewRAGContext() *RAGContext { return &RAGContext{} }

func (a *RAGContext) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.rag-context", Version: "1.0.0",
		Domain: "rag-context", Subdomain: "indirect-injection",
		Categories:    []string{"rag-security", "indirect-injection"},
		AnalysisTypes: []string{"rag-context"}, SupportedTypes: []string{"md", "txt", "json", "py", "js"},
	}
}

func (a *RAGContext) Rules() []skil.Rule {
	return []skil.Rule{
		{
			ID: RuleRAGProvenanceMissing, Title: "Untrusted writable RAG knowledge base without provenance", Category: "rag-security",
			Severity: skil.SeverityMedium, Analysis: "rag-context", AppliesTo: []string{"md", "txt", "json", "py", "js"},
			Description: "RAG vector store or memory retrieval accepts untrusted user input without provenance binding.",
			Remediation: "Ensure retrieved RAG context items include cryptographically signed or origin-verified metadata.",
		},
		{
			ID: RuleRAGBoundaryConfusion, Title: "Instruction/data boundary confusion in RAG prompt template", Category: "rag-security",
			Severity: skil.SeverityHigh, Analysis: "rag-context", AppliesTo: []string{"md", "txt", "json", "py", "js"},
			Description: "RAG context is injected directly into system prompt without clear structural delimiters.",
			Remediation: "Use strict XML delimiters or distinct message roles for retrieved RAG data.",
		},
		{
			ID: RuleRAGRetrievalExecFlow, Title: "Direct retrieval-to-command execution flow in RAG pipeline", Category: "rag-security",
			Severity: skil.SeverityHigh, Analysis: "rag-context", AppliesTo: []string{"md", "txt", "json", "py", "js"},
			Description: "Retrieved RAG context contents are passed directly to subprocess or code execution sinks.",
			Remediation: "Sanitize retrieved data before dereferencing into executable tool arguments.",
		},
	}
}

var (
	ragBoundaryRegex = regexp.MustCompile(`(?i)(System\s+Context:\s*\{context\}|\{retrieved_docs\}|\{rag_memory\})`)
	ragExecFlowRegex = regexp.MustCompile(`(?i)(exec\(retrieved|subprocess\.run\(.*retriev|eval\(doc\.content)`)
	ragStorageRegex  = regexp.MustCompile(`(?i)(vectorstore\.add_texts\(|db\.insert_document\(|memory\.save_context\()`)
)

func (a *RAGContext) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var findings []skil.Finding
	artifact := ac.Artifact

	for _, f := range artifact.Files {
		ext := strings.ToLower(f.Path)
		if !strings.HasSuffix(ext, ".md") && !strings.HasSuffix(ext, ".txt") && !strings.HasSuffix(ext, ".json") && !strings.HasSuffix(ext, ".py") && !strings.HasSuffix(ext, ".js") {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(f.Data)))
		lineNumber := 0

		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()

			if ragBoundaryRegex.MatchString(line) {
				findings = append(findings, skil.Finding{
					RuleID:      RuleRAGBoundaryConfusion,
					Severity:    skil.SeverityHigh,
					Title:       "Instruction/data boundary confusion in RAG prompt template",
					Message:     "Detected unconfined RAG context injection in prompt: " + strings.TrimSpace(line),
					Description: "RAG retrieved text is placed directly in system prompt instructions.",
					Location:    skil.Location{File: f.Path, StartLine: lineNumber, EndLine: lineNumber},
					Fingerprint: fingerprint(artifact.Name, RuleRAGBoundaryConfusion, f.Path, string(rune(lineNumber))),
					Remediation: "Enclose retrieved RAG items in strict XML tags (e.g., <rag_context>...</rag_context>).",
				})
			}

			if ragExecFlowRegex.MatchString(line) {
				findings = append(findings, skil.Finding{
					RuleID:      RuleRAGRetrievalExecFlow,
					Severity:    skil.SeverityHigh,
					Title:       "Direct retrieval-to-command execution flow in RAG pipeline",
					Message:     "Detected retrieved RAG text passed to execution sink: " + strings.TrimSpace(line),
					Description: "Retrieved documents are executed directly in subprocess/eval sinks.",
					Location:    skil.Location{File: f.Path, StartLine: lineNumber, EndLine: lineNumber},
					Fingerprint: fingerprint(artifact.Name, RuleRAGRetrievalExecFlow, f.Path, string(rune(lineNumber))),
					Remediation: "Never execute untrusted retrieved context as code.",
				})
			}

			if ragStorageRegex.MatchString(line) {
				findings = append(findings, skil.Finding{
					RuleID:      RuleRAGProvenanceMissing,
					Severity:    skil.SeverityMedium,
					Title:       "Untrusted writable RAG knowledge base without provenance",
					Message:     "Detected vectorstore/memory write operation: " + strings.TrimSpace(line),
					Description: "Vector store accepts raw text writes without origin provenance binding.",
					Location:    skil.Location{File: f.Path, StartLine: lineNumber, EndLine: lineNumber},
					Fingerprint: fingerprint(artifact.Name, RuleRAGProvenanceMissing, f.Path, string(rune(lineNumber))),
					Remediation: "Attach verified publisher provenance to all stored RAG documents.",
				})
			}
		}
	}

	return findings, nil
}
