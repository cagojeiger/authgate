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

func TestProtectedResourceMetadataURL(t *testing.T) {
	tests := []struct {
		name            string
		resourceURL     string
		wantMetadataURL string
		wantPath        string
	}{
		{
			name:            "root resource",
			resourceURL:     "https://host.example.com",
			wantMetadataURL: "https://host.example.com/.well-known/oauth-protected-resource",
			wantPath:        "/.well-known/oauth-protected-resource",
		},
		{
			name:            "path resource",
			resourceURL:     "https://host.example.com/mcp",
			wantMetadataURL: "https://host.example.com/.well-known/oauth-protected-resource/mcp",
			wantPath:        "/.well-known/oauth-protected-resource/mcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotPath, err := protectedResourceMetadataURL(tt.resourceURL)
			if err != nil {
				t.Fatalf("protectedResourceMetadataURL error: %v", err)
			}
			if gotURL != tt.wantMetadataURL {
				t.Fatalf("metadata url = %q, want %q", gotURL, tt.wantMetadataURL)
			}
			if gotPath != tt.wantPath {
				t.Fatalf("metadata path = %q, want %q", gotPath, tt.wantPath)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		name     string
		claims   *Claims
		required string
		want     bool
	}{
		{
			name:     "scope claim contains required",
			claims:   &Claims{Scope: "openid profile email"},
			required: "profile",
			want:     true,
		},
		{
			name:     "scp claim contains required",
			claims:   &Claims{Scp: []string{"openid", "email"}},
			required: "email",
			want:     true,
		},
		{
			name:     "missing required scope",
			claims:   &Claims{Scope: "openid profile"},
			required: "admin",
			want:     false,
		},
		{
			name:     "empty required scope bypasses check",
			claims:   &Claims{},
			required: "",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasScope(tt.claims, tt.required); got != tt.want {
				t.Fatalf("hasScope(%+v, %q) = %v, want %v", tt.claims, tt.required, got, tt.want)
			}
		})
	}
}
