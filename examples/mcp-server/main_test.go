package main

import "testing"

func TestContainsAudience(t *testing.T) {
	tests := []struct {
		name     string
		aud      any
		expected string
		want     bool
	}{
		{name: "single string match", aud: "https://mcp.example.com", expected: "https://mcp.example.com", want: true},
		{name: "single string mismatch", aud: "client-id", expected: "https://mcp.example.com", want: false},
		{name: "slice any match", aud: []any{"client-id", "https://mcp.example.com"}, expected: "https://mcp.example.com", want: true},
		{name: "slice string match", aud: []string{"client-id", "https://mcp.example.com"}, expected: "https://mcp.example.com", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAudience(tt.aud, tt.expected); got != tt.want {
				t.Fatalf("containsAudience(%v, %q) = %v, want %v", tt.aud, tt.expected, got, tt.want)
			}
		})
	}
}
