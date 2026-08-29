package cli

import (
	"fmt"
	"os"

	"github.com/domehahn/skil/internal/mcpinterceptor"
)

func (a *App) mcpIntercept(args []string) int {
	fs := newFlags("mcp intercept", a.Err)
	lockPath := fs.String("lock", ".skil/mcp-surface.lock.json", "path to MCP surface lock file")
	strict := fs.Bool("strict", true, "enforce strict blocking of unauthorized dynamic tools")

	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}

	interceptor, err := mcpinterceptor.NewInterceptor(mcpinterceptor.InterceptorOptions{
		SurfaceLockPath: *lockPath,
		Strict:          *strict,
	})
	if err != nil {
		return a.inputError(err)
	}

	if err := interceptor.RunStream(os.Stdin, a.Out, true); err != nil {
		return a.inputError(fmt.Errorf("mcp intercept stream: %w", err))
	}

	return ExitOK
}
