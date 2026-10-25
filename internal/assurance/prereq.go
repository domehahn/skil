package assurance

import (
	"fmt"
	"sort"
	"sync"

	"github.com/domehahn/skil/pkg/skil"
)

// PrerequisiteState is the outcome of initialising one analyzer prerequisite
// (rule pack, YARA compilation, AST parser, advisory database, schema, tool).
type PrerequisiteState string

const (
	PrerequisiteExpected    PrerequisiteState = "EXPECTED"
	PrerequisiteLoaded      PrerequisiteState = "LOADED"
	PrerequisiteRejected    PrerequisiteState = "REJECTED"
	PrerequisiteUnavailable PrerequisiteState = "UNAVAILABLE"
)

// Prerequisite identifies one thing an analyzer needs before its result can be
// trusted. Digest binds the loaded artifact (e.g. rule pack bytes).
type Prerequisite struct {
	Analyzer string            `json:"analyzer"`
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Digest   string            `json:"digest,omitempty"`
	State    PrerequisiteState `json:"state"`
	Reason   string            `json:"reason,omitempty"`
}

func (p Prerequisite) key() string { return p.Analyzer + "\x00" + p.Kind + "\x00" + p.Name }

// PrerequisiteLedger is safe for concurrent analyzer runs. A prerequisite must
// be Expect()ed before it can be Loaded; Load/Reject/Unavailable on an unknown
// key is recorded as a failure so concurrent analyzers cannot silently grow
// the loaded set.
type PrerequisiteLedger struct {
	mu    sync.Mutex
	items map[string]Prerequisite
	stray []string
}

func NewPrerequisiteLedger() *PrerequisiteLedger {
	return &PrerequisiteLedger{items: map[string]Prerequisite{}}
}

func (l *PrerequisiteLedger) Expect(analyzer, kind, name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p := Prerequisite{Analyzer: analyzer, Kind: kind, Name: name, State: PrerequisiteExpected}
	if _, exists := l.items[p.key()]; !exists {
		l.items[p.key()] = p
	}
}

func (l *PrerequisiteLedger) settle(analyzer, kind, name, digest, reason string, state PrerequisiteState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := Prerequisite{Analyzer: analyzer, Kind: kind, Name: name}.key()
	p, ok := l.items[key]
	if !ok {
		l.stray = append(l.stray, fmt.Sprintf("%s/%s/%s settled as %s without being expected", analyzer, kind, name, state))
		return
	}
	// A rejection or unavailability is sticky: a later "loaded" report cannot
	// erase it.
	if p.State == PrerequisiteRejected || p.State == PrerequisiteUnavailable {
		return
	}
	p.State, p.Digest, p.Reason = state, digest, reason
	l.items[key] = p
}

func (l *PrerequisiteLedger) Loaded(analyzer, kind, name, digest string) {
	l.settle(analyzer, kind, name, digest, "", PrerequisiteLoaded)
}
func (l *PrerequisiteLedger) Rejected(analyzer, kind, name, reason string) {
	l.settle(analyzer, kind, name, "", reason, PrerequisiteRejected)
}
func (l *PrerequisiteLedger) Unavailable(analyzer, kind, name, reason string) {
	l.settle(analyzer, kind, name, "", reason, PrerequisiteUnavailable)
}

// Snapshot returns a deterministic copy.
func (l *PrerequisiteLedger) Snapshot() []Prerequisite {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Prerequisite, 0, len(l.items))
	for _, p := range l.items {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// Complete is true only if at least one prerequisite was expected, every one is
// LOADED, and nothing settled without being expected.
func (l *PrerequisiteLedger) Complete() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.items) == 0 || len(l.stray) > 0 {
		return false
	}
	for _, p := range l.items {
		if p.State != PrerequisiteLoaded {
			return false
		}
	}
	return true
}

// ApplyPrerequisites downgrades an assurance report when any prerequisite is
// not LOADED. It can only lower assurance, never raise it, and it never
// mutates the input report.
func ApplyPrerequisites(report *skil.AssuranceReport, ledger *PrerequisiteLedger) *skil.AssuranceReport {
	if report == nil || ledger == nil {
		return report
	}
	out := *report
	out.Limitations = append([]skil.AssuranceLimitation(nil), report.Limitations...)
	items := ledger.Snapshot()
	failed := false
	for _, p := range items {
		if p.State == PrerequisiteLoaded {
			continue
		}
		failed = true
		cause := fmt.Sprintf("%s prerequisite %q is %s", p.Kind, p.Name, p.State)
		if p.Reason != "" {
			cause += ": " + p.Reason
		}
		out.Limitations = append(out.Limitations, skil.AssuranceLimitation{
			Subject: p.Name, Phase: "prerequisite", Cause: cause, Analyzer: p.Analyzer, Control: p.Analyzer,
			Dimensions:     []skil.AssuranceDimension{skil.DimensionControlExecution},
			Evidence:       []string{skil.DigestJSON(p)},
			DecisionEffect: "prevents COMPLETE assurance",
		})
	}
	if !ledger.Complete() {
		failed = true
		if len(items) == 0 {
			out.Limitations = append(out.Limitations, skil.AssuranceLimitation{
				Subject: "prerequisites", Phase: "prerequisite", Cause: "no analyzer prerequisites were declared",
				Dimensions:     []skil.AssuranceDimension{skil.DimensionControlExecution},
				DecisionEffect: "prevents COMPLETE assurance",
			})
		}
	}
	if failed && out.Outcome == skil.OutcomeComplete {
		out.Outcome = skil.OutcomePartial
		out.Proof.Outcome = skil.OutcomePartial
		out.Proof.Unresolved = append(append([]string(nil), out.Proof.Unresolved...), "analyzer prerequisites are not all loaded")
	}
	out.EvidenceDigest = skil.DigestJSON(struct {
		Base  string
		Items []Prerequisite
	}{report.EvidenceDigest, items})
	return &out
}
