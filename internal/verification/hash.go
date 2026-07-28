package verification

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func stable(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}
