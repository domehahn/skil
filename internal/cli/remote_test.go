package cli

import (
	"context"
	"strings"
	"testing"
)

func TestRemoteSourcesAreExplicitAndRejectPrivateHosts(t *testing.T) {
	if _, _, err := stageRemoteSource(context.Background(), "https://example.test/repo.git", false); err == nil ||
		!strings.Contains(err.Error(), "--allow-remote") {
		t.Fatalf("remote source was not explicit: %v", err)
	}
	if _, _, err := stageRemoteSource(context.Background(), "https://127.0.0.1/repo.git", true); err == nil ||
		!strings.Contains(err.Error(), "prohibited") {
		t.Fatalf("private remote source was not rejected: %v", err)
	}
}
