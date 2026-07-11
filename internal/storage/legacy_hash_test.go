//go:build integration

package storage

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashToken is the legacy plain SHA-256 token hash. Production code now keys
// every token lookup through crypto.Keys (RefreshHash/SessionHash/CodeHash);
// this helper survives only so integration tests can assert a stored hash is
// NOT the old unkeyed value.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
