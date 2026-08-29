package discover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type DriftEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // "component_added", "component_removed", "surface_drift"
	Message   string    `json:"message"`
	Component Component `json:"component,omitempty"`
}

type WorkspaceWatcher struct {
	WorkspaceRoot string
	Interval      time.Duration
}

func NewWorkspaceWatcher(workspaceRoot string, interval time.Duration) *WorkspaceWatcher {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &WorkspaceWatcher{
		WorkspaceRoot: workspaceRoot,
		Interval:      interval,
	}
}

func (w *WorkspaceWatcher) Watch(ctx context.Context, handler func(DriftEvent)) error {
	var lastState = make(map[string]string)

	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()

	// Initial scan
	w.poll(lastState, handler)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			w.poll(lastState, handler)
		}
	}
}

func (w *WorkspaceWatcher) poll(lastState map[string]string, handler func(DriftEvent)) {
	components, err := DiscoverWorkspace(w.WorkspaceRoot)
	if err != nil {
		return
	}

	currentState := make(map[string]string)
	for _, comp := range components {
		key := comp.Tool + ":" + string(comp.Kind) + ":" + comp.Name + ":" + comp.Path
		hashInput := key + ":" + comp.Command + ":" + fmt.Sprintf("%v", comp.Args)
		sum := sha256.Sum256([]byte(hashInput))
		digest := hex.EncodeToString(sum[:8])

		currentState[key] = digest

		if lastDigest, exists := lastState[key]; !exists {
			handler(DriftEvent{
				Timestamp: time.Now().UTC(),
				Type:      "component_added",
				Message:   fmt.Sprintf("new %s detected: %s (%s)", comp.Kind, comp.Name, comp.Tool),
				Component: comp,
			})
		} else if lastDigest != digest {
			handler(DriftEvent{
				Timestamp: time.Now().UTC(),
				Type:      "surface_drift",
				Message:   fmt.Sprintf("%s configuration drift detected: %s (%s)", comp.Kind, comp.Name, comp.Tool),
				Component: comp,
			})
		}
	}

	for key := range lastState {
		if _, exists := currentState[key]; !exists {
			handler(DriftEvent{
				Timestamp: time.Now().UTC(),
				Type:      "component_removed",
				Message:   fmt.Sprintf("component removed: %s", key),
			})
		}
	}

	// Update state
	for k, v := range currentState {
		lastState[k] = v
	}
}
