// Package resilience contains shared, bounded provider transport behavior.
package resilience

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Policy bounds retries for provider requests. Retries are only attempted
// when the request body can be replayed and the response is transient.
type Policy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

func DefaultPolicy() Policy {
	return Policy{MaxAttempts: 2, BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second}
}

// Do executes a provider request with bounded retry behavior. It preserves
// the final response body for the caller and closes transient response bodies
// before retrying. Retry-After is honored only within the configured maximum.
func Do(ctx context.Context, client *http.Client, request *http.Request, policy Policy) (*http.Response, error) {
	if client == nil {
		return nil, errors.New("provider HTTP client is nil")
	}
	if request == nil {
		return nil, errors.New("provider HTTP request is nil")
	}
	if policy.MaxAttempts < 1 {
		policy.MaxAttempts = 1
	}
	if policy.BaseDelay <= 0 {
		policy.BaseDelay = 100 * time.Millisecond
	}
	if policy.MaxDelay <= 0 {
		policy.MaxDelay = time.Second
	}
	for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
		current := request
		if attempt > 0 {
			current = request.Clone(ctx)
			if request.GetBody == nil {
				return nil, errors.New("provider request body cannot be replayed")
			}
			body, err := request.GetBody()
			if err != nil {
				return nil, err
			}
			current.Body = body
		}
		response, err := client.Do(current)
		if err == nil && !retryableStatus(response.StatusCode) {
			return response, nil
		}
		if attempt+1 >= policy.MaxAttempts {
			return response, err
		}
		retryAfter := time.Duration(0)
		if err == nil && response != nil {
			retryAfter = retryAfterDelay(response, policy.MaxDelay)
		}
		if response != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if retryAfter > 0 {
			if !wait(ctx, retryAfter) {
				return nil, ctx.Err()
			}
			continue
		}
		delay := policy.BaseDelay << attempt
		if delay > policy.MaxDelay {
			delay = policy.MaxDelay
		}
		if !wait(ctx, delay) {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("provider request attempts exhausted")
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= 500
}

func retryAfterDelay(response *http.Response, maximum time.Duration) time.Duration {
	value := response.Header.Get("Retry-After")
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds < 0 {
		return 0
	}
	delay := time.Duration(seconds) * time.Second
	if delay > maximum {
		return maximum
	}
	return delay
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
