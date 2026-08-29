package signing

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

type SessionContextOptions struct {
	SystemPrompt  string  `json:"system_prompt"`
	Temperature   float64 `json:"temperature"`
	Seed          int64   `json:"seed"`
	SessionMemory string  `json:"session_memory"`
}

func BindSessionDigest(attestation *skil.Attestation, opts SessionContextOptions) string {
	if attestation == nil {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(opts.SystemPrompt))
	h.Write([]byte(fmt.Sprintf("%f", opts.Temperature)))
	h.Write([]byte(fmt.Sprintf("%d", opts.Seed)))
	h.Write([]byte(opts.SessionMemory))

	sessionDigest := fmt.Sprintf("sha256:%x", h.Sum(nil))

	ev := skil.Evidence{
		Type:          "session_bound_digest",
		Producer:      "skil",
		ProducerVer:   "1.0.0",
		SubjectDigest: attestation.Subject.SHA256,
		Timestamp:     time.Now().UTC(),
		PayloadDigest: sessionDigest,
	}

	attestation.Evidence = append(attestation.Evidence, ev)

	return sessionDigest
}
