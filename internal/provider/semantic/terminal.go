package semantic

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// TerminalOutcome is the explicit end state of a provider exchange. A closed
// connection or HTTP 200 is never by itself COMPLETE.
type TerminalOutcome string

const (
	OutcomeComplete         TerminalOutcome = "COMPLETE"
	OutcomeTransportError   TerminalOutcome = "TRANSPORT_ERROR"
	OutcomeCancelled        TerminalOutcome = "CANCELLED"
	OutcomeDeadlineExceeded TerminalOutcome = "DEADLINE_EXCEEDED"
	OutcomeRetryExhausted   TerminalOutcome = "RETRY_EXHAUSTED"
	OutcomeSchemaInvalid    TerminalOutcome = "SCHEMA_INVALID"
	OutcomeProtocolError    TerminalOutcome = "PROTOCOL_ERROR"
)

// decodeStructured strictly decodes the provider's structured output. It
// requires exactly one JSON object with a non-null "findings" array and no
// other fields or trailing data. Anything else is an error, so an invalid
// response can never be mistaken for a valid response with zero findings.
func decodeStructured(content string) (semanticResult, error) {
	var out semanticResult
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return out, errors.New("empty structured output")
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var raw struct {
		Findings *[]semanticFinding `json:"findings"`
	}
	if err := dec.Decode(&raw); err != nil {
		return out, fmt.Errorf("invalid structured output: %w", err)
	}
	if dec.More() {
		return out, errors.New("trailing data after structured output")
	}
	if _, err := dec.Token(); err != io.EOF {
		return out, errors.New("trailing data after structured output")
	}
	if raw.Findings == nil {
		return out, errors.New("structured output lacks required findings array")
	}
	out.Findings = *raw.Findings
	return out, nil
}

// ValidateStructuredResponse checks that a raw provider response string adheres
// strictly to the structured findings schema without unknown fields, null
// findings, or trailing tokens.
func ValidateStructuredResponse(content string) error {
	_, err := decodeStructured(content)
	return err
}

// StreamResult is the verified terminal state of an SSE-style stream.
type StreamResult struct {
	Outcome    TerminalOutcome `json:"outcome"`
	Detail     string          `json:"detail,omitempty"`
	Events     int             `json:"events"`
	Matched    int             `json:"matched_events"`
	Rejected   int             `json:"rejected_events"`
	Content    string          `json:"-"`
	FinishSeen string          `json:"finish_reason,omitempty"`
}

const maxStreamEvents = 100000

// ReadStream consumes a text/event-stream body and reports whether the stream
// terminated by an explicit, protocol-valid completion signal:
//   - OpenAI-style: a chunk with finish_reason "stop" followed by "[DONE]"
//     (a "length"/"content_filter" finish is not COMPLETE)
//   - AG-UI: RUN_FINISHED (RUN_ERROR is a PROTOCOL_ERROR)
//
// EOF without such a signal is TRANSPORT_ERROR: a closed connection is not
// proof of completion.
func ReadStream(r io.Reader) StreamResult {
	res := StreamResult{}
	var content strings.Builder
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	done, runFinished := false, false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		res.Events++
		if res.Events > maxStreamEvents {
			res.Outcome, res.Detail = OutcomeProtocolError, "event count exceeds limit"
			return res
		}
		if done || runFinished {
			res.Outcome, res.Detail = OutcomeProtocolError, "data received after terminal event"
			return res
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			done = true
			res.Matched++
			continue
		}
		var ev struct {
			Type    string `json:"type"`
			Message string `json:"message"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			res.Rejected++
			res.Outcome, res.Detail = OutcomeProtocolError, "malformed event payload"
			return res
		}
		switch ev.Type {
		case "RUN_FINISHED":
			runFinished = true
			res.Matched++
			continue
		case "RUN_ERROR":
			res.Rejected++
			res.Outcome, res.Detail = OutcomeProtocolError, "AG-UI RUN_ERROR: "+ev.Message
			return res
		}
		if len(ev.Choices) == 0 {
			res.Rejected++
			continue
		}
		res.Matched++
		content.WriteString(ev.Choices[0].Delta.Content)
		if fr := ev.Choices[0].FinishReason; fr != nil && *fr != "" {
			res.FinishSeen = *fr
		}
	}
	res.Content = content.String()
	if err := sc.Err(); err != nil {
		res.Outcome, res.Detail = OutcomeTransportError, err.Error()
		return res
	}
	switch {
	case runFinished:
		res.Outcome = OutcomeComplete
	case done && res.FinishSeen == "stop":
		res.Outcome = OutcomeComplete
	case done && res.FinishSeen == "":
		res.Outcome, res.Detail = OutcomeProtocolError, "[DONE] without a provider finish_reason"
	case done:
		res.Outcome, res.Detail = OutcomeProtocolError, "provider finish_reason "+res.FinishSeen+" is not a normal completion"
	default:
		res.Outcome, res.Detail = OutcomeTransportError, "stream ended without a terminal event"
	}
	return res
}

// Attempt is one provider attempt with a stable identity and terminal outcome.
type Attempt struct {
	ID               string          `json:"id"`
	Outcome          TerminalOutcome `json:"outcome"`
	OutputEmitted    bool            `json:"output_emitted"`
	OutputDigest     string          `json:"output_digest,omitempty"`
	ConsumedBudgetNS int64           `json:"consumed_ns,omitempty"`
}

// AttemptLedger enforces retry integrity: a retry is permitted only while no
// output has been emitted by any prior attempt, within a bounded budget. It is
// safe for concurrent use.
type AttemptLedger struct {
	mu         sync.Mutex
	maxRetries int
	attempts   []Attempt
}

func NewAttemptLedger(maxRetries int) *AttemptLedger {
	if maxRetries < 0 {
		maxRetries = 0
	}
	return &AttemptLedger{maxRetries: maxRetries}
}

// Begin registers a new attempt or refuses it.
func (l *AttemptLedger) Begin(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if id == "" {
		return errors.New("attempt requires an identity")
	}
	for _, a := range l.attempts {
		if a.ID == id {
			return fmt.Errorf("attempt %q already recorded", id)
		}
		if a.Outcome == OutcomeComplete {
			return errors.New("a prior attempt already completed")
		}
		if a.OutputEmitted {
			return errors.New("retry refused: a prior attempt already emitted output")
		}
	}
	if len(l.attempts) > l.maxRetries {
		return errors.New("retry budget exhausted")
	}
	l.attempts = append(l.attempts, Attempt{ID: id})
	return nil
}

// Finish records the outcome of the most recent attempt with that id.
func (l *AttemptLedger) Finish(id string, outcome TerminalOutcome, outputEmitted bool, outputDigest string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.attempts {
		if l.attempts[i].ID == id {
			if l.attempts[i].Outcome != "" {
				return fmt.Errorf("attempt %q already finished", id)
			}
			l.attempts[i].Outcome, l.attempts[i].OutputEmitted, l.attempts[i].OutputDigest = outcome, outputEmitted, outputDigest
			return nil
		}
	}
	return fmt.Errorf("unknown attempt %q", id)
}

// Terminal summarises the exchange. COMPLETE only if the final attempt
// completed with no unfinished attempt; if the retry budget is spent without
// completion the result is RETRY_EXHAUSTED.
func (l *AttemptLedger) Terminal() TerminalOutcome {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.attempts) == 0 {
		return OutcomeProtocolError
	}
	last := l.attempts[len(l.attempts)-1]
	if last.Outcome == "" {
		return OutcomeProtocolError
	}
	if last.Outcome == OutcomeComplete {
		return OutcomeComplete
	}
	if len(l.attempts) > l.maxRetries {
		return OutcomeRetryExhausted
	}
	return last.Outcome
}

func (l *AttemptLedger) Attempts() []Attempt {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := append([]Attempt(nil), l.attempts...)
	return out
}

// RecoverToolCall conservatively normalizes a malformed provider tool call. It
// accepts exactly one JSON object with a string "name" from the allowlist and
// an object "arguments" (optionally delivered as a JSON-encoded string). It
// never derives a command from prose; anything ambiguous is rejected. The
// original text is preserved for evidence.
type RecoveredToolCall struct {
	Original  string         `json:"original"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func RecoverToolCall(original string, allowed map[string]bool) (RecoveredToolCall, error) {
	text := strings.TrimSpace(original)
	if text == "" || len(text) > 64*1024 {
		return RecoveredToolCall{}, errors.New("tool call is empty or oversized")
	}
	var probe struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&probe); err != nil {
		return RecoveredToolCall{}, errors.New("tool call is not a single well-formed JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return RecoveredToolCall{}, errors.New("trailing data after tool call")
	}
	if !allowed[probe.Name] {
		return RecoveredToolCall{}, fmt.Errorf("tool %q is not authorized", probe.Name)
	}
	args := map[string]any{}
	raw := bytes.TrimSpace(probe.Arguments)
	if len(raw) > 0 && raw[0] == '"' { // arguments delivered as an encoded string
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return RecoveredToolCall{}, errors.New("arguments string is malformed")
		}
		raw = []byte(s)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return RecoveredToolCall{}, errors.New("tool call has no arguments object")
	}
	d2 := json.NewDecoder(bytes.NewReader(raw))
	if err := d2.Decode(&args); err != nil || args == nil {
		return RecoveredToolCall{}, errors.New("arguments are not a JSON object")
	}
	if _, err := d2.Token(); err != io.EOF {
		return RecoveredToolCall{}, errors.New("trailing data after arguments")
	}
	return RecoveredToolCall{Original: original, Name: probe.Name, Arguments: args}, nil
}
