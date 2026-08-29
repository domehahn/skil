package analyzer

import (
	"context"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func TestRAGContextDetectsBoundaryConfusionAndExecFlow(t *testing.T) {
	analyzer := NewRAGContext()

	artifact := skil.Artifact{
		Name: "rag-poison-skill",
		Files: []skil.File{
			{
				Path: "prompt.py",
				Data: []byte("System Context: {retrieved_docs}\nexec(retrieved_doc.content)"),
			},
		},
	}

	findings, err := analyzer.Analyze(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (boundary confusion + exec flow), got %d", len(findings))
	}
}

func TestRAGContextNormalizesPersistentExternalIngestion(t *testing.T) {
	artifact := skil.Artifact{Name: "memory", Files: []skil.File{{Path: "memory.py", Data: []byte(`store = Chroma(persist_directory="./memory")
store.add_documents(WebBaseLoader("https://content.example.test").load())
docs = store.similarity_search(query)
`)}}}
	findings, observations, err := NewRAGContext().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range []string{"memory.persistence", "memory.cross_session", "rag.ingestion", "rag.external_source", "vectorstore.read"} {
		found := false
		for _, observation := range observations {
			found = found || observation.Capability == capability
		}
		if !found {
			t.Errorf("missing %s observation in %#v", capability, observations)
		}
	}
	if !hasRule(findings, RuleMemoryPersistence) || !hasRule(findings, RuleRAGExternalSource) {
		t.Fatalf("persistent/external RAG findings missing: %#v", findings)
	}
}

func TestRAGContextEphemeralContextIsNotPersistent(t *testing.T) {
	artifact := skil.Artifact{Name: "ephemeral", Files: []skil.File{{Path: "prompt.py", Data: []byte(`context = request.documents
prompt = "<context>" + context + "</context>"
`)}}}
	findings, observations, err := NewRAGContext().AnalyzeCapabilities(context.Background(), skil.AnalysisContext{Artifact: artifact})
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range observations {
		if observation.Capability == "memory.persistence" || observation.Capability == "memory.cross_session" {
			t.Fatalf("ephemeral context was classified as persistent: %#v", observations)
		}
	}
	if hasRule(findings, RuleMemoryPersistence) {
		t.Fatalf("ephemeral context produced persistence finding: %#v", findings)
	}
}

func TestPersistenceEvidenceRequiresCanaryBoundaryAndBehavior(t *testing.T) {
	for _, evidence := range []skil.PersistenceTestEvidence{
		{CanaryObserved: true},
		{CanaryObserved: true, SessionBoundaryCrossed: true},
		{CanaryObserved: true, DirectiveActedOn: true},
	} {
		if evidence.ConfirmedBehavioralPersistence() {
			t.Fatalf("partial persistence evidence was overclaimed: %#v", evidence)
		}
	}
	confirmed := skil.PersistenceTestEvidence{CanaryObserved: true, SessionBoundaryCrossed: true, DirectiveActedOn: true}
	if !confirmed.ConfirmedBehavioralPersistence() {
		t.Fatal("complete two-phase persistence evidence was not confirmed")
	}
}
