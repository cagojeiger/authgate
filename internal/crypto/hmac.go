package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// KeyedHash computes a hex-encoded HMAC-SHA256 over parts joined with a NUL
// domain separator, keyed by pepper. It is deterministic (same input -> same
// output) so it can back a UNIQUE lookup column, while being one-way: a leaked
// hash does not reveal the original value (ADR-002).
//
// The pepper must be kept outside the database. Use a NUL separator so that
// Hash("a","bc") and Hash("ab","c") do not collide.
func KeyedHash(pepper []byte, parts ...string) string {
	mac := hmac.New(sha256.New, pepper)
	for i, p := range parts {
		if i > 0 {
			mac.Write([]byte{0})
		}
		mac.Write([]byte(p))
	}
	return hex.EncodeToString(mac.Sum(nil))
}
