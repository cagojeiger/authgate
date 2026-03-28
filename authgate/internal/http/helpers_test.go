package http

import (
	"crypto/sha256"
	"strings"
	"testing"

	"authgate/internal/domain"
)

func TestSha256Sum_Characterization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "empty string",
			input:    "",
			expected: sha256.New().Sum(nil),
		},
		{
			name:     "simple string",
			input:    "test",
			expected: sha256.New().Sum([]byte("test")),
		},
		{
			name:     "code verifier example",
			input:    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			expected: sha256.New().Sum([]byte("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")),
		},
		{
			name:     "unicode string",
			input:    "hello 世界",
			expected: sha256.New().Sum([]byte("hello 世界")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := domain.SHA256Sum(tt.input)

			h := sha256.New()
			h.Write([]byte(tt.input))
			expected := h.Sum(nil)

			if string(result) != string(expected) {
				t.Errorf("domain.SHA256Sum(%q) = %x, want %x", tt.input, result, expected)
			}
		})
	}
}

func TestContainsScope_Characterization(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		scope    string
		expected bool
	}{
		{
			name:     "scope exists in list",
			scopes:   []string{"openid", "profile", "email"},
			scope:    "profile",
			expected: true,
		},
		{
			name:     "scope does not exist",
			scopes:   []string{"openid", "profile"},
			scope:    "email",
			expected: false,
		},
		{
			name:     "empty scopes list",
			scopes:   []string{},
			scope:    "openid",
			expected: false,
		},
		{
			name:     "nil scopes list",
			scopes:   nil,
			scope:    "openid",
			expected: false,
		},
		{
			name:     "empty scope search",
			scopes:   []string{"openid", "profile"},
			scope:    "",
			expected: false,
		},
		{
			name:     "exact match only - substring should not match",
			scopes:   []string{"openid", "profile_email"},
			scope:    "email",
			expected: false,
		},
		{
			name:     "case sensitive",
			scopes:   []string{"openid", "profile"},
			scope:    "Profile",
			expected: false,
		},
		{
			name:     "single element match",
			scopes:   []string{"openid"},
			scope:    "openid",
			expected: true,
		},
		{
			name:     "single element no match",
			scopes:   []string{"openid"},
			scope:    "profile",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := domain.ContainsScope(tt.scopes, tt.scope)
			if result != tt.expected {
				t.Errorf("domain.ContainsScope(%v, %q) = %v, want %v", tt.scopes, tt.scope, result, tt.expected)
			}
		})
	}
}

func TestContainsScope_UsedInProduction(t *testing.T) {
	t.Run("openid check for ID token generation", func(t *testing.T) {
		scopes := []string{"openid", "profile", "email"}
		if !domain.ContainsScope(scopes, "openid") {
			t.Error("Expected to find 'openid' in standard scope list")
		}
	})

	t.Run("openid check in device flow", func(t *testing.T) {
		scopes := []string{"openid", "profile"}
		if !domain.ContainsScope(scopes, "openid") {
			t.Error("Expected to find 'openid' in device flow scopes")
		}
	})

	t.Run("no openid scope", func(t *testing.T) {
		scopes := []string{"profile", "email"}
		if domain.ContainsScope(scopes, "openid") {
			t.Error("Should not find 'openid' when not in scope list")
		}
	})
}

func TestGenerateUserCode_Characterization(t *testing.T) {
	codes := make(map[string]bool)

	for i := 0; i < 100; i++ {
		code := domain.GenerateUserCode()

		if len(code) != 9 {
			t.Errorf("domain.GenerateUserCode() returned code with length %d, expected 9: %s", len(code), code)
		}

		parts := strings.Split(code, "-")
		if len(parts) != 2 {
			t.Errorf("domain.GenerateUserCode() returned code without proper hyphen separator: %s", code)
			continue
		}

		if len(parts[0]) != 4 || len(parts[1]) != 4 {
			t.Errorf("domain.GenerateUserCode() returned code with wrong part lengths: %s", code)
		}

		allowedChars := "BCDFGHJKLMNPQRSTVWXYZ"
		for _, char := range code {
			if char == '-' {
				continue
			}
			if !strings.ContainsRune(allowedChars, char) {
				t.Errorf("domain.GenerateUserCode() returned code with invalid character '%c': %s", char, code)
			}
		}

		if codes[code] {
			t.Logf("Warning: duplicate code generated (this is statistically unlikely but possible): %s", code)
		}
		codes[code] = true
	}
}

func TestGenerateDeviceCode_Characterization(t *testing.T) {
	codes := make(map[string]bool)

	for i := 0; i < 100; i++ {
		code := domain.GenerateDeviceCode()

		if code == "" {
			t.Error("domain.GenerateDeviceCode() returned empty string")
		}

		if strings.Contains(code, "+") || strings.Contains(code, "/") || strings.Contains(code, "=") {
			t.Errorf("domain.GenerateDeviceCode() returned code with invalid base64 URL characters: %s", code)
		}

		if len(code) < 40 || len(code) > 50 {
			t.Errorf("domain.GenerateDeviceCode() returned code with unexpected length %d: %s", len(code), code)
		}

		if codes[code] {
			t.Errorf("domain.GenerateDeviceCode() returned duplicate code (this should not happen with 32 random bytes): %s", code)
		}
		codes[code] = true
	}
}
