package semantic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/domehahn/skil/pkg/skil"
)

func providerWith(t *testing.T, reportedModel, finalURL string) *Provider {
	t.Helper()
	client := &http.Client{Transport: semanticRoundTrip(func(r *http.Request) (*http.Response, error) {
		m := map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": `{"findings":[]}`}}}}
		if reportedModel != "" {
			m["model"] = reportedModel
		}
		body, _ := json.Marshal(m)
		req := r
		if finalURL != "" {
			u, _ := url.Parse(finalURL)
			req = r.Clone(r.Context())
			req.URL = u
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header), Request: req}, nil
	})}
	p, err := New(Config{Endpoint: "https://semantic.test/v1/chat/completions", Model: "gpt-x", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func analyze(t *testing.T, p *Provider) skil.SemanticAnalysis {
	t.Helper()
	res, err := p.AnalyzeUntrustedDetailed(context.Background(), skil.SemanticRequest{ArtifactDigest: "d", Files: map[string]string{"SKILL.md": "x"}, NoTools: true})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestObservedInvocationValidatesWhenWireMatchesAuthorization(t *testing.T) {
	res := analyze(t, providerWith(t, "gpt-x", ""))
	if res.Invocation == nil {
		t.Fatal("no invocation evidence from an observed response")
	}
	if err := res.Invocation.Validate(); err != nil {
		t.Fatal(err)
	}
	if res.Invocation.Destination.ModelIdentity != "gpt-x" || res.Invocation.TransmittedConfigDigest == "" {
		t.Fatalf("%+v", res.Invocation)
	}
}

func TestUnreportedOrDifferentModelCannotValidate(t *testing.T) {
	for name, reported := range map[string]string{"unreported": "", "substituted": "cheap-model"} {
		res := analyze(t, providerWith(t, reported, ""))
		if res.Invocation == nil || res.Invocation.Validate() == nil {
			t.Errorf("%s: unverified model validated: %+v", name, res.Invocation)
		}
	}
}

func TestEffectiveEndpointDifferingFromAuthorizedCannotValidate(t *testing.T) {
	res := analyze(t, providerWith(t, "gpt-x", "https://elsewhere.test/v1/chat/completions"))
	if res.Invocation == nil || res.Invocation.Validate() == nil {
		t.Fatalf("destination drift validated: %+v", res.Invocation)
	}
}

func TestDegradedExchangeCarriesNoInvocationEvidence(t *testing.T) {
	res := analyze(t, providerReturning(t, `{}`))
	if !res.Diagnostics.Incomplete {
		t.Fatal("setup")
	}
	if res.Invocation != nil {
		t.Fatal("a rejected response must not yield invocation evidence")
	}
}

func TestToolsNotDisabledOnTheWireIsADeviation(t *testing.T) {
	ev := observedInvocation(observation{Provider: "p", AuthorizedEndpoint: "https://a.test/x", Effective: "https://a.test/x",
		RequestedModel: "m", ReportedModel: "m", ToolChoice: "auto"})
	if ev.Validate() == nil {
		t.Fatal("tools enabled must not validate")
	}
}
