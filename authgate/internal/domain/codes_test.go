package domain

import (
	"strings"
	"testing"
)

func TestGenerateCode(t *testing.T) {
	codes := make(map[string]bool)

	for i := 0; i < 100; i++ {
		code := GenerateCode()

		if code == "" {
			t.Error("GenerateCode() returned empty string")
		}

		if codes[code] {
			t.Errorf("GenerateCode() returned duplicate: %s", code)
		}
		codes[code] = true
	}
}

func TestGenerateDeviceCode(t *testing.T) {
	codes := make(map[string]bool)

	for i := 0; i < 100; i++ {
		code := GenerateDeviceCode()

		if code == "" {
			t.Error("GenerateDeviceCode() returned empty string")
		}

		if strings.Contains(code, "=") {
			t.Errorf("GenerateDeviceCode() contains padding: %s", code)
		}

		if strings.ContainsAny(code, "+/") {
			t.Errorf("GenerateDeviceCode() has unsafe chars: %s", code)
		}

		if codes[code] {
			t.Errorf("GenerateDeviceCode() returned duplicate: %s", code)
		}
		codes[code] = true
	}
}

func TestGenerateUserCode(t *testing.T) {
	codes := make(map[string]bool)
	allowedChars := "BCDFGHJKLMNPQRSTVWXYZ"

	for i := 0; i < 100; i++ {
		code := GenerateUserCode()

		if len(code) != 9 {
			t.Errorf("GenerateUserCode() length = %d, want 9: %s", len(code), code)
		}

		if code[4] != '-' {
			t.Errorf("GenerateUserCode() missing hyphen at position 4: %s", code)
		}

		for _, c := range code {
			if c == '-' {
				continue
			}
			if !strings.ContainsRune(allowedChars, c) {
				t.Errorf("GenerateUserCode() has invalid char '%c': %s", c, code)
			}
		}

		if codes[code] {
			t.Logf("Warning: duplicate user code generated: %s", code)
		}
		codes[code] = true
	}
}

func TestGenerateUserCode_Format(t *testing.T) {
	code := GenerateUserCode()

	parts := strings.Split(code, "-")
	if len(parts) != 2 {
		t.Fatalf("GenerateUserCode() format invalid: %s", code)
	}

	if len(parts[0]) != 4 || len(parts[1]) != 4 {
		t.Errorf("GenerateUserCode() part lengths invalid: %s", code)
	}
}
