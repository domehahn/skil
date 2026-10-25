package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/domehahn/skil/pkg/skil"
)

// ProviderInputBudget accounts for the complete serialized wire payload sent
// to an external semantic/LLM provider, not merely the raw artifact file size.
type ProviderInputBudget struct {
	MaxSerializedBytes int `json:"max_serialized_bytes"`
	MaxEstimatedTokens int `json:"max_estimated_tokens"`
}

// ProviderWireAccounting breaks down every component contributing to the
// serialized provider request payload.
type ProviderWireAccounting struct {
	SystemInstructionsBytes int    `json:"system_instructions_bytes"`
	PromptTemplateBytes     int    `json:"prompt_template_bytes"`
	ArtifactContentBytes    int    `json:"artifact_content_bytes"`
	MetadataBytes           int    `json:"metadata_bytes"`
	OutputSchemaBytes       int    `json:"output_schema_bytes"`
	ToolDefinitionsBytes    int    `json:"tool_definitions_bytes"`
	TotalSerializedBytes    int    `json:"total_serialized_bytes"`
	EstimatedTokens         int    `json:"estimated_tokens"`
	Exceeded                bool   `json:"exceeded"`
	Reason                  string `json:"reason,omitempty"`
}

// EvaluateProviderInputBudget computes the total serialized wire size and token
// estimate for a provider request and enforces the configured budget.
func EvaluateProviderInputBudget(budget ProviderInputBudget, systemPrompt, promptTemplate, artifactContent, metadataJSON, schemaJSON, toolsJSON []byte) (ProviderWireAccounting, error) {
	acc := ProviderWireAccounting{
		SystemInstructionsBytes: len(systemPrompt),
		PromptTemplateBytes:     len(promptTemplate),
		ArtifactContentBytes:    len(artifactContent),
		MetadataBytes:           len(metadataJSON),
		OutputSchemaBytes:       len(schemaJSON),
		ToolDefinitionsBytes:    len(toolsJSON),
	}
	acc.TotalSerializedBytes = acc.SystemInstructionsBytes +
		acc.PromptTemplateBytes +
		acc.ArtifactContentBytes +
		acc.MetadataBytes +
		acc.OutputSchemaBytes +
		acc.ToolDefinitionsBytes
	// Conservative token estimate (~4 UTF-8 bytes per token, rounded up).
	acc.EstimatedTokens = (acc.TotalSerializedBytes + 3) / 4

	if budget.MaxSerializedBytes > 0 && acc.TotalSerializedBytes > budget.MaxSerializedBytes {
		acc.Exceeded = true
		acc.Reason = fmt.Sprintf("total serialized provider input (%d bytes) exceeds budget (%d bytes)", acc.TotalSerializedBytes, budget.MaxSerializedBytes)
		return acc, errors.New(acc.Reason)
	}
	if budget.MaxEstimatedTokens > 0 && acc.EstimatedTokens > budget.MaxEstimatedTokens {
		acc.Exceeded = true
		acc.Reason = fmt.Sprintf("estimated provider input tokens (%d) exceed budget (%d)", acc.EstimatedTokens, budget.MaxEstimatedTokens)
		return acc, errors.New(acc.Reason)
	}
	return acc, nil
}

// ResourceAccounting records deterministic resource consumption and self-protection
// bounds across an entire scan execution.
type ResourceAccounting struct {
	FilesDiscovered        int      `json:"files_discovered"`
	FilesLoaded            int      `json:"files_loaded"`
	BytesLoaded            int64    `json:"bytes_loaded"`
	NestedArchiveDepth     int      `json:"nested_archive_depth"`
	NestedMembersExpanded  int      `json:"nested_members_expanded"`
	NestedBytesExpanded    int64    `json:"nested_bytes_expanded"`
	ASTNodesVisited        int      `json:"ast_nodes_visited"`
	TaintFixpointPasses    int      `json:"taint_fixpoint_passes"`
	SemanticRequestsSent   int      `json:"semantic_requests_sent"`
	ProviderInputWireBytes int      `json:"provider_input_wire_bytes"`
	SelfProtectionTriggers []string `json:"self_protection_triggers,omitempty"`
	Digest                 string   `json:"digest"`
}

// Finalize computes the canonical digest of the resource accounting ledger and
// downgrades the provided AssuranceReport if any self-protection bound triggered.
func (r *ResourceAccounting) Finalize(report *skil.AssuranceReport, subject string) {
	copyLedger := *r
	copyLedger.Digest = ""
	raw, _ := json.Marshal(copyLedger)
	sum := sha256.Sum256(raw)
	r.Digest = "sha256:" + hex.EncodeToString(sum[:])

	if report == nil || len(r.SelfProtectionTriggers) == 0 {
		return
	}
	for _, trig := range r.SelfProtectionTriggers {
		report.Limitations = append(report.Limitations, skil.AssuranceLimitation{
			Subject:        subject,
			Phase:          "self-protection-budget",
			Cause:          trig,
			Dimensions:     []skil.AssuranceDimension{skil.DimensionArtifactInspection, skil.DimensionControlExecution},
			Evidence:       []string{r.Digest},
			DecisionEffect: "prevents COMPLETE assurance",
		})
	}
	if report.Outcome == skil.OutcomeComplete {
		report.Outcome = skil.OutcomePartial
	}
	report.Proof.Outcome = report.Outcome
	report.Proof.Unresolved = append(report.Proof.Unresolved, r.SelfProtectionTriggers...)
}
