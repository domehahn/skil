package resilience

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestDoRetriesTransientResponseAndReplaysBody(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		body, _ := io.ReadAll(request.Body)
		if string(body) != "payload" {
			t.Fatalf("body=%q", body)
		}
		status := http.StatusServiceUnavailable
		if calls.Load() == 2 {
			status = http.StatusOK
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	})}
	request, err := http.NewRequest(http.MethodPost, "https://provider.test", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := Do(context.Background(), client, request, Policy{MaxAttempts: 2, BaseDelay: time.Nanosecond, MaxDelay: time.Millisecond})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("response=%v err=%v", response, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestDoDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("bad")), Request: request}, nil
	})}
	request, _ := http.NewRequest(http.MethodGet, "https://provider.test", nil)
	response, err := Do(context.Background(), client, request, DefaultPolicy())
	if err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("response=%v err=%v", response, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}
