package domain

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// GenerateCode generates a random authorization code.
// Returns a base64 URL-encoded string of 32 random bytes.
// This function is NOT pure - it uses crypto/rand for randomness.
func GenerateCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// GenerateDeviceCode generates a random device code for device flow.
// Returns a base64 Raw URL-encoded string of 32 random bytes (no padding).
// This function is NOT pure - it uses crypto/rand for randomness.
func GenerateDeviceCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateUserCode generates a user-friendly verification code for device flow.
// Returns a code in the format XXXX-XXXX using only letters B, C, D, F, G, H, J, K, L, M, N, P, Q, R, S, T, V, W, X, Y, Z
// (letters that are unambiguous in most fonts and can't be confused with digits).
// This function is NOT pure - it uses crypto/rand for randomness.
func GenerateUserCode() string {
	const chars = "BCDFGHJKLMNPQRSTVWXYZ"
	var code strings.Builder
	for i := 0; i < 8; i++ {
		if i == 4 {
			code.WriteByte('-')
		}
		b := make([]byte, 1)
		rand.Read(b)
		code.WriteByte(chars[b[0]%byte(len(chars))])
	}
	return code.String()
}
