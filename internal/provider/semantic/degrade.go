package semantic

import "github.com/domehahn/skil/pkg/skil"

// degradedResult builds a SemanticAnalysis representing "this pass
// produced no usable findings because of a provider- or response-level
// problem" — a transport failure, an oversized or malformed response, a
// non-2xx HTTP status, the provider truncating its own output, or more
// findings than the accepted maximum — rather than a Go error. Treating
// these as a hard error would abort the entire scan and discard every
// other analyzer's already-computed findings; reporting them as an
// incomplete pass instead degrades semantic-provider coverage (and,
// through the assurance closure, the overall result to UNKNOWN) while
// leaving the rest of the scan intact — the correct fail-closed shape for
// a probabilistic provider's own hiccup, as opposed to a genuine local
// programming error.
func degradedResult(reason string) skil.SemanticAnalysis {
	return skil.SemanticAnalysis{
		Diagnostics: skil.SemanticDiagnostics{
			Rejected: 1, Incomplete: true,
			Errors: []skil.SemanticValidationError{{Index: -1, Message: reason}},
		},
	}
}
