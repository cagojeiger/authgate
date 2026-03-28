package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHashToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:  "simple token",
			token: "test-token-123",
			expected: func() string {
				hash := sha256.Sum256([]byte("test-token-123"))
				return hex.EncodeToString(hash[:])
			}(),
		},
		{
			name:  "empty token",
			token: "",
			expected: func() string {
				hash := sha256.Sum256([]byte(""))
				return hex.EncodeToString(hash[:])
			}(),
		},
		{
			name:  "long token",
			token: "a-very-long-token-with-many-characters-and-symbols-!@#$%",
			expected: func() string {
				hash := sha256.Sum256([]byte("a-very-long-token-with-many-characters-and-symbols-!@#$%"))
				return hex.EncodeToString(hash[:])
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashToken(tt.token)
			if result != tt.expected {
				t.Errorf("HashToken(%q) = %q, want %q", tt.token, result, tt.expected)
			}

			if len(result) != 64 {
				t.Errorf("HashToken(%q) returned %d characters, expected 64", tt.token, len(result))
			}
		})
	}
}

func TestSHA256Sum(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "simple", input: "test"},
		{name: "pkce-example", input: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SHA256Sum(tt.input)

			if len(result) != 32 {
				t.Errorf("SHA256Sum(%q) returned %d bytes, expected 32", tt.input, len(result))
			}

			result2 := SHA256Sum(tt.input)
			if string(result) != string(result2) {
				t.Errorf("SHA256Sum(%q) not consistent", tt.input)
			}
		})
	}
}
