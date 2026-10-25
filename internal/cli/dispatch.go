package cli

import "context"

type commandHandler func(context.Context, []string) int

// commandHandlers is the composition boundary for the CLI. Command families
// are assembled independently so adding a command does not grow the central
// execution method or alter unrelated dispatch cases.
func (a *App) commandHandlers() map[string]commandHandler {
	handlers := make(map[string]commandHandler)
	for name, handler := range a.analysisCommands() {
		handlers[name] = handler
	}
	for name, handler := range a.assuranceCommands() {
		handlers[name] = handler
	}
	for name, handler := range a.lifecycleCommands() {
		handlers[name] = handler
	}
	for name, handler := range a.developerCommands() {
		handlers[name] = handler
	}
	return handlers
}

func (a *App) analysisCommands() map[string]commandHandler {
	return map[string]commandHandler{
		"validate": func(_ context.Context, args []string) int { return a.validate(args) },
		"lint":     func(_ context.Context, args []string) int { return a.lint(args) },
		"lint-all": func(_ context.Context, args []string) int { return a.lintAll(args) },
		"scan":     func(ctx context.Context, args []string) int { return a.scan(ctx, args) },
		"scan-all": func(ctx context.Context, args []string) int { return a.scanAll(ctx, args) },
		"explain":  func(ctx context.Context, args []string) int { return a.explain(ctx, args) },
		"verify":   func(ctx context.Context, args []string) int { return a.verify(ctx, args) },
		"eval": func(ctx context.Context, args []string) int {
			if len(args) > 0 && args[0] == "run" {
				return RunEval(args, a.Out, a.Err)
			}
			return a.evaluate(ctx, args)
		},
		"assure":       func(ctx context.Context, args []string) int { return a.assure(ctx, args) },
		"analyzers":    func(_ context.Context, args []string) int { return a.analyzers(args) },
		"capabilities": func(_ context.Context, args []string) int { return a.capabilities(args) },
		"inspect":      func(_ context.Context, args []string) int { return a.inspect(args) },
		"completeness": func(_ context.Context, args []string) int { return RunCompleteness(args, a.Out, a.Err) },
	}
}

func (a *App) assuranceCommands() map[string]commandHandler {
	return map[string]commandHandler{
		"continuous": func(ctx context.Context, args []string) int { return a.continuous(ctx, args) },
		"attest":     func(ctx context.Context, args []string) int { return a.attest(ctx, args) },
		"evidence":   func(_ context.Context, args []string) int { return a.evidence(args) },
		"policy":     func(ctx context.Context, args []string) int { return a.policyCheck(ctx, args) },
		"gate":       func(_ context.Context, args []string) int { return a.gate(args) },
		"contract":   func(ctx context.Context, args []string) int { return a.contract(ctx, args) },
		"receipt":    func(_ context.Context, args []string) int { return RunReceipt(args, a.Out, a.Err) },
	}
}

func (a *App) lifecycleCommands() map[string]commandHandler {
	return map[string]commandHandler{
		"compose": func(ctx context.Context, args []string) int {
			if len(args) > 0 && args[0] == "assure" {
				return a.composeAssure(ctx, append([]string{}, args[1:]...))
			}
			return a.compose(ctx, args)
		},
		"serve":      func(ctx context.Context, args []string) int { return a.serve(ctx, args) },
		"mcp":        func(ctx context.Context, args []string) int { return a.mcp(ctx, args) },
		"registry":   func(ctx context.Context, args []string) int { return a.registryCommand(ctx, args) },
		"admission":  func(ctx context.Context, args []string) int { return a.admission(ctx, args) },
		"provenance": func(_ context.Context, args []string) int { return a.provenance(args) },
		"key":        func(_ context.Context, args []string) int { return a.key(args) },
		"package":    func(_ context.Context, args []string) int { return a.packageBuild(args) },
		"install":    func(ctx context.Context, args []string) int { return a.install(ctx, args) },
		"update":     func(ctx context.Context, args []string) int { return a.update(ctx, args) },
		"uninstall":  func(_ context.Context, args []string) int { return a.uninstall(args) },
		"lock":       func(_ context.Context, args []string) int { return a.lock(args) },
		"sbom":       func(_ context.Context, args []string) int { return a.sbom(args) },
		"discover":   func(_ context.Context, args []string) int { return a.discover(args) },
		"revoke":     func(_ context.Context, args []string) int { return a.revoke(args) },
	}
}

func (a *App) developerCommands() map[string]commandHandler {
	return map[string]commandHandler{
		"trust":     func(_ context.Context, args []string) int { return RunTrust(args, a.Out, a.Err) },
		"card":      func(_ context.Context, args []string) int { return RunCard(args, a.Out, a.Err) },
		"optimize":  func(_ context.Context, args []string) int { return RunOptimize(args, a.Out, a.Err) },
		"graph":     func(_ context.Context, args []string) int { return RunGraph(args, a.Out, a.Err) },
		"compare":   func(_ context.Context, args []string) int { return RunCompare(args, a.Out, a.Err) },
		"drift":     func(_ context.Context, args []string) int { return RunCompare(args, a.Out, a.Err) },
		"probe":     func(_ context.Context, args []string) int { return RunProbe(args, a.Out, a.Err) },
		"redteam":   func(_ context.Context, args []string) int { return RunProbe(args, a.Out, a.Err) },
		"proxy":     func(_ context.Context, args []string) int { return RunProxy(args, a.Out, a.Err) },
		"telemetry": func(_ context.Context, args []string) int { return RunTelemetry(args, a.Out, a.Err) },
		"rules":     func(_ context.Context, args []string) int { return a.rules(args) },
		"conform":   func(_ context.Context, args []string) int { return a.conform(args) },
		"baseline":  func(ctx context.Context, args []string) int { return a.baselineCreate(ctx, args) },
		"fix":       func(_ context.Context, args []string) int { return a.fix(args) },
		"watch":     func(ctx context.Context, args []string) int { return a.watch(ctx, args) },
		"hook":      func(_ context.Context, args []string) int { return a.hook(args) },
		"ci":        func(_ context.Context, args []string) int { return a.ci(args) },
		"mesh":      func(_ context.Context, args []string) int { return a.mesh(args) },
		"stego":     func(_ context.Context, args []string) int { return a.stego(args) },
		"sandbox":   func(_ context.Context, args []string) int { return a.sandbox(args) },
		"zk":        func(ctx context.Context, args []string) int { return a.zk(ctx, args) },
	}
}
