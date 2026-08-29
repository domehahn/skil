package discover

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWorkspaceWatcherDetectsNewComponentAndDrift(t *testing.T) {
	tempDir := t.TempDir()
	claudeDir := filepath.Join(tempDir, ".claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(claudeDir, "mcp.json")
	if err := os.WriteFile(configPath, []byte(`{"mcpServers": {"test": {"command": "echo"}}}`), 0644); err != nil {
		t.Fatal(err)
	}

	watcher := NewWorkspaceWatcher(tempDir, 50*time.Millisecond)

	var events []DriftEvent
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_ = watcher.Watch(ctx, func(e DriftEvent) {
		events = append(events, e)
	})

	if len(events) == 0 {
		t.Fatalf("expected workspace watcher to emit initial component_added event, got none")
	}

	if events[0].Type != "component_added" {
		t.Fatalf("unexpected event type: %s", events[0].Type)
	}
}
