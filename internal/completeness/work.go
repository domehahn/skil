package completeness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

type WorkState string

const (
	WorkComplete        WorkState = "COMPLETE"
	WorkPartial         WorkState = "PARTIAL"
	WorkExcluded        WorkState = "EXCLUDED"
	WorkUnsupported     WorkState = "UNSUPPORTED"
	WorkFailed          WorkState = "FAILED"
	WorkBudgetExhausted WorkState = "BUDGET_EXHAUSTED"
)

type WorkUnit struct {
	ID                string    `json:"id" yaml:"id"`
	Stage             string    `json:"stage" yaml:"stage"`
	Subject           string    `json:"subject" yaml:"subject"`
	Artifact          string    `json:"artifact,omitempty" yaml:"artifact,omitempty"`
	Analyzer          string    `json:"analyzer" yaml:"analyzer"`
	State             WorkState `json:"state" yaml:"state"`
	Evidence          []string  `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Limitation        string    `json:"limitation,omitempty" yaml:"limitation,omitempty"`
	Allocated         int64     `json:"allocated,omitempty" yaml:"allocated,omitempty"`
	Consumed          int64     `json:"consumed,omitempty" yaml:"consumed,omitempty"`
	CompletedWork     int64     `json:"completed_work,omitempty" yaml:"completed_work,omitempty"`
	RemainingWork     int64     `json:"remaining_work,omitempty" yaml:"remaining_work,omitempty"`
	TerminationReason string    `json:"termination_reason,omitempty" yaml:"termination_reason,omitempty"`
}

type DetailedWorkLedger struct {
	Planned []WorkUnit `json:"planned" yaml:"planned"`
	Digest  string     `json:"digest" yaml:"digest"`
}

func (l DetailedWorkLedger) Finalize(maxUnits int) (DetailedWorkLedger, error) {
	if maxUnits <= 0 {
		maxUnits = 100_000
	}
	if len(l.Planned) > maxUnits {
		return l, errors.New("work ledger budget exhausted")
	}
	seen := make(map[string]bool, len(l.Planned))
	for _, unit := range l.Planned {
		if unit.ID == "" || unit.Stage == "" || unit.Subject == "" || unit.Analyzer == "" {
			return l, errors.New("work unit identity, stage, subject, and analyzer are required")
		}
		if seen[unit.ID] {
			return l, errors.New("duplicate work unit identity")
		}
		seen[unit.ID] = true
		switch unit.State {
		case WorkComplete, WorkPartial, WorkExcluded, WorkUnsupported, WorkFailed, WorkBudgetExhausted:
		default:
			return l, errors.New("work unit has no accounted outcome")
		}
		if unit.State != WorkComplete && unit.Limitation == "" && unit.TerminationReason == "" {
			return l, errors.New("incomplete work unit requires a limitation or termination reason")
		}
	}
	sort.Slice(l.Planned, func(i, j int) bool { return l.Planned[i].ID < l.Planned[j].ID })
	b, _ := json.Marshal(l.Planned)
	sum := sha256.Sum256(b)
	l.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return l, nil
}

func (l DetailedWorkLedger) Complete() bool {
	if len(l.Planned) == 0 {
		return false
	}
	for _, u := range l.Planned {
		if u.State != WorkComplete {
			return false
		}
	}
	return true
}

type BudgetStage string

const (
	BudgetDiscovery    BudgetStage = "discovery"
	BudgetStatic       BudgetStage = "static"
	BudgetArtifact     BudgetStage = "artifact"
	BudgetDerived      BudgetStage = "derived_view"
	BudgetSemantic     BudgetStage = "semantic"
	BudgetVerification BudgetStage = "verification"
	BudgetBehavioral   BudgetStage = "behavioral"
	BudgetRedTeam      BudgetStage = "red_team"
	BudgetRuntime      BudgetStage = "runtime_evaluation"
)

// HierarchicalBudget is a deterministic unit ledger layered on top of the
// existing byte/count/time AnalysisBudget. A child reservation can never
// exceed the remaining parent amount.
type HierarchicalBudget struct {
	Stage     BudgetStage                    `json:"stage" yaml:"stage"`
	Limit     int64                          `json:"limit" yaml:"limit"`
	Consumed  int64                          `json:"consumed" yaml:"consumed"`
	Children  map[string]*HierarchicalBudget `json:"children,omitempty" yaml:"children,omitempty"`
	Exhausted bool                           `json:"exhausted" yaml:"exhausted"`
}

func NewHierarchicalBudget(stage BudgetStage, limit int64) *HierarchicalBudget {
	if limit < 0 {
		limit = 0
	}
	return &HierarchicalBudget{Stage: stage, Limit: limit, Children: map[string]*HierarchicalBudget{}}
}

func (b *HierarchicalBudget) Remaining() int64 {
	if b == nil || b.Consumed >= b.Limit {
		return 0
	}
	return b.Limit - b.Consumed
}

func (b *HierarchicalBudget) Reserve(name string, stage BudgetStage, childLimit int64) (*HierarchicalBudget, error) {
	if b == nil || name == "" || childLimit < 0 {
		return nil, errors.New("invalid child budget reservation")
	}
	if _, exists := b.Children[name]; exists {
		return nil, errors.New("duplicate child budget")
	}
	effective := childLimit
	if effective > b.Remaining() {
		effective = b.Remaining()
	}
	child := NewHierarchicalBudget(stage, effective)
	child.Exhausted = childLimit > effective
	b.Consumed += effective
	b.Children[name] = child
	return child, nil
}

func (b *HierarchicalBudget) Consume(amount int64) error {
	if b == nil || amount < 0 {
		return errors.New("invalid budget consumption")
	}
	if amount > b.Remaining() {
		b.Consumed = b.Limit
		b.Exhausted = true
		return errors.New("analysis budget exhausted")
	}
	b.Consumed += amount
	return nil
}
