package semantic

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func sse(lines ...string) string { return strings.Join(lines, "\n\n") + "\n\n" }

func chunk(content, finish string) string {
	if finish == "" {
		return fmt.Sprintf(`data: {"choices":[{"delta":{"content":%q},"finish_reason":null}]}`, content)
	}
	return fmt.Sprintf(`data: {"choices":[{"delta":{"content":%q},"finish_reason":%q}]}`, content, finish)
}

func TestStreamTerminalStates(t *testing.T) {
	cases := []struct {
		name string
		body string
		want TerminalOutcome
	}{
		{"normal completion", sse(chunk(`{"findings":`, ""), chunk(`[]}`, "stop"), "data: [DONE]"), OutcomeComplete},
		{"closed without terminal event", sse(chunk(`{"find`, "")), OutcomeTransportError},
		{"done without finish reason", sse(chunk("x", ""), "data: [DONE]"), OutcomeProtocolError},
		{"truncated by length", sse(chunk("x", "length"), "data: [DONE]"), OutcomeProtocolError},
		{"content filter", sse(chunk("x", "content_filter"), "data: [DONE]"), OutcomeProtocolError},
		{"agui finished", sse(`data: {"type":"RUN_STARTED"}`, `data: {"type":"RUN_FINISHED"}`), OutcomeComplete},
		{"agui error", sse(`data: {"type":"RUN_ERROR","message":"boom"}`), OutcomeProtocolError},
		{"data after done", sse(chunk("x", "stop"), "data: [DONE]", chunk("late", "")), OutcomeProtocolError},
		{"malformed event", sse("data: {not json"), OutcomeProtocolError},
		{"empty stream", "", OutcomeTransportError},
	}
	for _, c := range cases {
		if got := ReadStream(strings.NewReader(c.body)); got.Outcome != c.want {
			t.Errorf("%s: got %s (%s) want %s", c.name, got.Outcome, got.Detail, c.want)
		}
	}
}

func TestStreamAccumulatesContentAndCountsEvents(t *testing.T) {
	r := ReadStream(strings.NewReader(sse(chunk(`{"findings":`, ""), chunk(`[]}`, "stop"), "data: [DONE]")))
	if r.Content != `{"findings":[]}` || r.Events != 3 || r.Matched != 3 {
		t.Fatalf("%+v", r)
	}
	if _, err := decodeStructured(r.Content); err != nil {
		t.Fatal(err)
	}
}

func TestRetryIntegrity(t *testing.T) {
	l := NewAttemptLedger(2)
	if err := l.Begin("a1"); err != nil {
		t.Fatal(err)
	}
	_ = l.Finish("a1", OutcomeTransportError, false, "")
	if err := l.Begin("a2"); err != nil {
		t.Fatalf("retry before any output must be allowed: %v", err)
	}
	_ = l.Finish("a2", OutcomeTransportError, true, "sha256:partial")
	if err := l.Begin("a3"); err == nil {
		t.Fatal("retry after partial output must be refused")
	}
	if l.Terminal() == OutcomeComplete {
		t.Fatal("partial stream cannot be COMPLETE")
	}
}

func TestRetryBudgetAndDuplicateIdentity(t *testing.T) {
	l := NewAttemptLedger(1)
	for _, id := range []string{"a", "b"} {
		if err := l.Begin(id); err != nil {
			t.Fatal(err)
		}
		_ = l.Finish(id, OutcomeTransportError, false, "")
	}
	if err := l.Begin("c"); err == nil {
		t.Fatal("budget must be enforced")
	}
	if l.Terminal() != OutcomeRetryExhausted {
		t.Fatalf("got %s", l.Terminal())
	}
	if err := l.Begin("a"); err == nil {
		t.Fatal("attempt identity must be unique")
	}
}

func TestCompletedAttemptEndsRetries(t *testing.T) {
	l := NewAttemptLedger(3)
	_ = l.Begin("a")
	_ = l.Finish("a", OutcomeComplete, true, "d")
	if l.Begin("b") == nil || l.Terminal() != OutcomeComplete {
		t.Fatal("no attempts after completion")
	}
}

func TestUnfinishedAttemptIsNotComplete(t *testing.T) {
	l := NewAttemptLedger(1)
	_ = l.Begin("a")
	if l.Terminal() == OutcomeComplete {
		t.Fatal("unfinished attempt")
	}
	if NewAttemptLedger(1).Terminal() == OutcomeComplete {
		t.Fatal("no attempts")
	}
}

func TestAttemptLedgerConcurrency(t *testing.T) {
	l := NewAttemptLedger(1000)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _ = l.Begin(fmt.Sprintf("a%d", i)) }(i)
	}
	wg.Wait()
	if len(l.Attempts()) != 50 {
		t.Fatalf("%d", len(l.Attempts()))
	}
}

func TestToolCallRecovery(t *testing.T) {
	allowed := map[string]bool{"read_file": true}
	ok, err := RecoverToolCall(`{"name":"read_file","arguments":"{\"path\":\"a.md\"}"}`, allowed)
	if err != nil || ok.Name != "read_file" || ok.Arguments["path"] != "a.md" || !strings.Contains(ok.Original, `\"path\"`) {
		t.Fatalf("%+v %v", ok, err)
	}
	for name, in := range map[string]string{
		"prose command":     `run rm -rf / to clean up`,
		"unauthorized tool": `{"name":"shell","arguments":{"cmd":"id"}}`,
		"trailing":          `{"name":"read_file","arguments":{"path":"a"}} ; curl evil`,
		"no arguments":      `{"name":"read_file"}`,
		"array args":        `{"name":"read_file","arguments":[1]}`,
		"unknown field":     `{"name":"read_file","arguments":{},"cmd":"id"}`,
		"empty":             ``,
	} {
		if _, err := RecoverToolCall(in, allowed); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
