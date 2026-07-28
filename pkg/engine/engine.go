// Package engine exposes composable scan orchestration for applications and
// third-party analyzers. The CLI is only one consumer of this API.
package engine

import (
	"context"

	"github.com/domehahn/skil/internal/analyzer"
	"github.com/domehahn/skil/pkg/skil"
)

type Registry struct{ inner *analyzer.Registry }

// New creates a registry with all deterministic built-in analyzers.
func New(vulnerabilities skil.VulnerabilityProvider) *Registry {
	return &Registry{inner: analyzer.DefaultRegistry(vulnerabilities)}
}

// Register adds an external analyzer. Analyzer IDs must be globally unique.
func (r *Registry) Register(item skil.Analyzer) error { return r.inner.Register(item) }

func (r *Registry) Analyzers() []skil.AnalyzerMetadata { return r.inner.Metadata() }

func (r *Registry) Scan(ctx context.Context, input skil.AnalysisContext) (skil.ScanResult, error) {
	return r.inner.Scan(ctx, input)
}

func Rules() []skil.Rule { return analyzer.BuiltinRules() }
