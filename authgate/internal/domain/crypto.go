package domain

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashToken creates a SHA256 hash of a token for secure storage.
// This function is pure - it has no side effects and always returns the same output for the same input.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// SHA256Sum returns the SHA256 hash of the input data as a byte slice.
// This is used for PKCE code challenge verification.
// This function is pure - it has no side effects and always returns the same output for the same input.
func SHA256Sum(data string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}
