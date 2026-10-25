package semantic

import (
	"net/http"
	"sort"

	"github.com/domehahn/skil/pkg/skil"
)

// observation is the set of facts a provider actually observed for one
// exchange. Nothing here is read back from configuration except the
// authorized/requested values it is compared against.
type observation struct {
	Provider              string
	AuthorizedEndpoint    string
	Effective             string // URL of the request that produced the response
	RequestedModel        string
	ReportedModel         string // model the provider says it ran
	Credentialed          bool
	Redirected            bool
	RequestBody           []byte
	ResponseContent       []byte
	RequestedCapabilities []string
	Capabilities          []string // capabilities effectively applied
	ToolChoice            string
}

func effectiveURL(r *http.Response) string {
	if r == nil || r.Request == nil || r.Request.URL == nil {
		return ""
	}
	return r.Request.URL.String()
}

// observedInvocation converts an observation to EffectiveInvocationEvidence.
// Every divergence between what was authorized/requested and what was observed
// is recorded as a Deviation, which makes EffectiveInvocationEvidence.Validate
// fail, so an unverified exchange cannot support COMPLETE assurance.
func observedInvocation(o observation) skil.EffectiveInvocationEvidence {
	var deviations []string
	if o.Effective == "" {
		deviations = append(deviations, "effective endpoint was not observed")
	}
	if o.ReportedModel == "" {
		deviations = append(deviations, "provider did not report the effective model")
	} else if o.ReportedModel != o.RequestedModel {
		deviations = append(deviations, "effective model "+o.ReportedModel+" differs from requested model "+o.RequestedModel)
	}
	if o.ToolChoice != "none" {
		deviations = append(deviations, "tool use was not disabled on the wire")
	}
	deviations = append(deviations, missing(o.RequestedCapabilities, o.Capabilities)...)
	sort.Strings(deviations)

	scope := "none"
	if o.Credentialed {
		scope = "bearer"
	}
	reqCfg := skil.DigestJSON(struct {
		Model, Endpoint string
		Capabilities    []string
	}{o.RequestedModel, o.AuthorizedEndpoint, o.RequestedCapabilities})
	effCfg := skil.DigestJSON(struct {
		Model, Endpoint string
		Capabilities    []string
	}{o.ReportedModel, o.Effective, o.Capabilities})
	transmitted := skil.DigestJSON(string(o.RequestBody))
	response := skil.DigestJSON(string(o.ResponseContent))
	model := o.ReportedModel
	return skil.EffectiveInvocationEvidence{
		InvocationID:            skil.DigestJSON(struct{ Req, Resp string }{transmitted, response}),
		RequestedConfigDigest:   reqCfg,
		ResolvedConfigDigest:    effCfg,
		TransmittedConfigDigest: transmitted,
		AcceptedConfigDigest:    effCfg,
		ResponseSemanticsDigest: response,
		Deviations:              deviations,
		Destination: skil.VerificationDestinationBinding{
			AuthorizedProvider: o.Provider, AuthorizedEndpoint: o.AuthorizedEndpoint,
			EffectiveProvider: o.Provider, EffectiveEndpoint: o.Effective,
			CredentialScope: scope, ModelIdentity: model,
			RequestConfigDigest: reqCfg, EvidenceProjectionDigest: response,
			Redirected: o.Redirected,
		},
	}
}

func missing(requested, effective []string) []string {
	have := map[string]bool{}
	for _, c := range effective {
		have[c] = true
	}
	var out []string
	for _, c := range requested {
		if !have[c] {
			out = append(out, "requested capability "+c+" was not effectively applied")
		}
	}
	return out
}
