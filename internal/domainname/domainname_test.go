package domainname

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	valid := []string{
		"example.com",
		"Example.COM",
		"a.b.c.example.com",
		"xn--80ak6aa92e.example.com",
		"my-host.example.com",
		"com",
		strings.Repeat("a", 63) + ".com",
	}
	for _, name := range valid {
		if !Valid(name) {
			t.Errorf("Valid(%q) = false, want true", name)
		}
	}

	invalid := map[string]string{
		"empty":           "",
		"trailing dot":    "example.com.",
		"leading dot":     ".example.com",
		"empty label":     "example..com",
		"leading hyphen":  "-example.com",
		"trailing hyphen": "example-.com",
		"underscore":      "exa_mple.com",
		"scheme":          "https://example.com",
		"path":            "example.com/",
		"port":            "example.com:443",
		"space":           "example .com",
		"unicode":         "例え.jp",
		"full-width":      "ｅxample.com",
		"kelvin sign":     "Korp.com",
		"label too long":  strings.Repeat("a", 64) + ".com",
		"name too long":   strings.Repeat("a.", 127) + "com",
		"wildcard":        "*.example.com",
		"at sign":         "a@example.com",
	}
	for name, value := range invalid {
		if Valid(value) {
			t.Errorf("%s: Valid(%q) = true, want false", name, value)
		}
	}
}
