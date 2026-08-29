package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/domehahn/skil/internal/discover"
)

func (a *App) watch(ctx context.Context, args []string) int {
	fs := newFlags("watch", a.Err)
	workspace := fs.String("workspace", ".", "workspace directory to watch")
	intervalStr := fs.String("interval", "2s", "poll interval duration")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	interval, err := time.ParseDuration(*intervalStr)
	if err != nil {
		return a.inputError(fmt.Errorf("invalid interval duration: %w", err))
	}

	watcher := discover.NewWorkspaceWatcher(*workspace, interval)
	fmt.Fprintf(a.Out, "Watching workspace %s for agent configuration drift (interval: %s)...\n", *workspace, interval)

	err = watcher.Watch(ctx, func(e discover.DriftEvent) {
		fmt.Fprintf(a.Out, "[%s] %s: %s\n", e.Timestamp.Format("15:04:05"), e.Type, e.Message)
	})

	if err != nil && err != context.Canceled {
		return a.internalError(err)
	}

	return ExitOK
}
