package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

const (
	RuleRAGProvenanceMissing = "SKIL-RAG-001"
	RuleRAGBoundaryConfusion = "SKIL-RAG-002"
	RuleRAGRetrievalExecFlow = "SKIL-RAG-003"
	RuleMemoryPersistence    = "SKIL-MEMORY-PERSISTENCE-001"
	RuleRAGExternalSource    = "SKIL-RAG-INGESTION-001"
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
		{ID: RuleMemoryPersistence, Title: "Persistent cross-session agent memory configured", Category: "memory-security", Severity: skil.SeverityMedium, Analysis: "rag-context", AppliesTo: []string{"json", "py", "js"}, Description: "Agent memory or vector state is persisted across sessions.", Remediation: "Declare persistence, scope retention, isolate tenants, and require provenance for stored content."},
		{ID: RuleRAGExternalSource, Title: "External content is ingested into agent context", Category: "rag-security", Severity: skil.SeverityMedium, Analysis: "rag-context", AppliesTo: []string{"json", "py", "js"}, Description: "A RAG pipeline automatically ingests an external source into agent context.", Remediation: "Validate source provenance, content type, tenant boundary, and ingestion policy before indexing."},
	}
}

var (
	ragBoundaryRegex = regexp.MustCompile(`(?i)(System\s+Context:\s*\{context\}|\{retrieved_docs\}|\{rag_memory\})`)
	ragExecFlowRegex = regexp.MustCompile(`(?i)(exec\(retrieved|subprocess\.run\(.*retriev|eval\(doc\.content)`)
	ragStorageRegex  = regexp.MustCompile(`(?i)(vectorstore\.add_texts\(|db\.insert_document\(|memory\.save_context\()`)
	ragReadRegex     = regexp.MustCompile(`(?i)(similarity_search\(|vectorstore\.(get|search|query)\(|retriever\.invoke\()`)
	persistenceRegex = regexp.MustCompile(`(?i)(persist_directory|memory\.save_context\(|\.persist\(\)|sqlite|chroma|pinecone|weaviate|qdrant|redis.*memory)`)
	ingestionRegex   = regexp.MustCompile(`(?i)(add_documents\(|add_texts\(|index_documents\(|directoryloader\(|webbaseloader\(|s3.*loader)`)
	externalRAGRegex = regexp.MustCompile(`(?i)(webbaseloader\(|s3.*loader|https?://[^\s"']+)`)
)

func (a *RAGContext) Analyze(ctx context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	findings, _, err := a.AnalyzeCapabilities(ctx, ac)
	return findings, err
}

func (a *RAGContext) AnalyzeCapabilities(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, []skil.CapabilityObservation, error) {
	var findings []skil.Finding
	var observations []skil.CapabilityObservation
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
				observations = appendRAGObservation(observations, "vectorstore.write", line, f.Path, lineNumber)
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
			if ragReadRegex.MatchString(line) {
				observations = appendRAGObservation(observations, "vectorstore.read", line, f.Path, lineNumber)
			}
			if ingestionRegex.MatchString(line) {
				observations = appendRAGObservation(observations, "rag.ingestion", line, f.Path, lineNumber)
			}
			if persistenceRegex.MatchString(line) {
				observations = appendRAGObservation(observations, "memory.persistence", line, f.Path, lineNumber)
				observations = appendRAGObservation(observations, "memory.cross_session", line, f.Path, lineNumber)
				findings = append(findings, makeFinding(RulePattern{Rule: a.ruleByID(RuleMemoryPersistence), Confidence: .9}, f, lineNumber, line))
			}
			if externalRAGRegex.MatchString(line) && ingestionRegex.MatchString(line) {
				observations = appendRAGObservation(observations, "rag.external_source", line, f.Path, lineNumber)
				findings = append(findings, makeFinding(RulePattern{Rule: a.ruleByID(RuleRAGExternalSource), Confidence: .9}, f, lineNumber, line))
			}
		}
		if strings.HasSuffix(ext, ".json") {
			var config any
			if err := json.Unmarshal(f.Data, &config); err != nil {
				return nil, nil, err
			}
			observations = inspectRAGConfig(config, f.Path, observations)
		}
	}
	sort.Slice(observations, func(i, j int) bool {
		a, b := observations[i], observations[j]
		return a.Location.File+"\x00"+a.Capability+"\x00"+a.Value < b.Location.File+"\x00"+b.Capability+"\x00"+b.Value
	})
	return findings, observations, nil
}

func (a *RAGContext) ruleByID(id string) skil.Rule {
	for _, rule := range a.Rules() {
		if rule.ID == id {
			return rule
		}
	}
	return skil.Rule{ID: id}
}

func appendRAGObservation(items []skil.CapabilityObservation, capability, value, file string, line int) []skil.CapabilityObservation {
	value = strings.TrimSpace(value)
	for _, item := range items {
		if item.Capability == capability && item.Value == value && item.Location.File == file && item.Location.StartLine == line {
			return items
		}
	}
	return append(items, skil.CapabilityObservation{Capability: capability, Value: value, Location: skil.Location{File: file, StartLine: line, EndLine: line}, Analyzer: "builtin.rag-context"})
}

func inspectRAGConfig(value any, file string, observations []skil.CapabilityObservation) []skil.CapabilityObservation {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			lower := strings.ToLower(key)
			line := 1
			switch {
			case strings.Contains(lower, "persist") || strings.Contains(lower, "cross_session") || strings.Contains(lower, "memory_store"):
				observations = appendRAGObservation(observations, "memory.persistence", key, file, line)
				observations = appendRAGObservation(observations, "memory.cross_session", key, file, line)
			case strings.Contains(lower, "ingest") || strings.Contains(lower, "index"):
				observations = appendRAGObservation(observations, "rag.ingestion", key, file, line)
			case strings.Contains(lower, "external_source") || strings.Contains(lower, "source_url"):
				observations = appendRAGObservation(observations, "rag.external_source", key, file, line)
			}
			observations = inspectRAGConfig(child, file, observations)
		}
	case []any:
		for _, child := range typed {
			observations = inspectRAGConfig(child, file, observations)
		}
	}
	return observations
}
