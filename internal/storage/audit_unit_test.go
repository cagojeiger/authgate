package storage

import (
	"context"
	"reflect"
	"testing"
)

func TestNormalizeIPAddress(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "ipv4", in: "172.64.151.232", want: "172.64.151.232"},
		{name: "ipv4 host port", in: "172.64.151.232:63603", want: "172.64.151.232"},
		{name: "ipv6", in: "::1", want: "::1"},
		{name: "ipv6 host port", in: "[::1]:63603", want: "::1"},
		{name: "bracketed ipv6 no port", in: "[::1]", want: "::1"},
		{name: "ipv4 mapped ipv6", in: "::ffff:172.64.151.232", want: "::ffff:172.64.151.232"},
		{name: "xff first address", in: "198.51.100.1, 10.0.0.1", want: "198.51.100.1"},
		{name: "xff first address with spaces", in: " 198.51.100.1 , 10.0.0.1", want: "198.51.100.1"},
		{name: "xff first address with port", in: "198.51.100.1:443, 10.0.0.1", want: "198.51.100.1"},
		{name: "unix socket", in: "unix", want: ""},
		{name: "hostname", in: "localhost:8080", want: ""},
		{name: "cidr", in: "198.51.100.1/24", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeIPAddress(tt.in); got != tt.want {
				t.Fatalf("normalizeIPAddress(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeAuditMetadata_AllowsKnownKeysOnly(t *testing.T) {
	metadata := map[string]any{
		"channel":        "browser",
		"client_id":      "client-1",
		"client_name":    "Client One",
		"session_id":     "sess-1",
		"reused_session": true,
		"email":          "person@example.com",
		"access_token":   "secret-token",
	}

	got := (&Storage{}).sanitizeAuditMetadata(context.Background(), "auth.login", metadata)
	want := map[string]any{
		"channel":     "browser",
		"client_id":   "client-1",
		"client_name": "Client One",
		// session_id is stored hashed, never as the raw bearer (ADR-002).
		"session_id":     hashToken("sess-1"),
		"reused_session": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sanitized metadata = %#v, want %#v", got, want)
	}
	if got["session_id"] == "sess-1" {
		t.Fatal("session_id stored as raw bearer; want hashed")
	}
}

func TestSanitizeAuditMetadata_UnknownEventDropsMetadata(t *testing.T) {
	got := (&Storage{}).sanitizeAuditMetadata(context.Background(), "custom.event", map[string]any{
		"client_id": "client-1",
	})
	if got != nil {
		t.Fatalf("unknown event metadata = %#v, want nil", got)
	}
}

func TestSanitizeAuditMetadata_EmptyResultReturnsNil(t *testing.T) {
	got := (&Storage{}).sanitizeAuditMetadata(context.Background(), "auth.login", map[string]any{
		"email": "person@example.com",
	})
	if got != nil {
		t.Fatalf("disallowed-only metadata = %#v, want nil", got)
	}
}
