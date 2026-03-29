package op

import (
	"testing"

	zop "github.com/zitadel/oidc/v3/pkg/op"
)

func TestStorage_CompileCheck(t *testing.T) {
	var _ zop.Storage = &Storage{}
	var _ zop.DeviceAuthorizationStorage = &Storage{}
}

func TestRefreshTokenRequest_Interface(t *testing.T) {
	var _ zop.RefreshTokenRequest = &refreshTokenRequest{}
}

func TestRefreshTokenRequest_Fields(t *testing.T) {
	r := &refreshTokenRequest{
		subject:  "user-123",
		clientID: "client-456",
		scopes:   []string{"openid", "profile"},
	}

	if r.GetSubject() != "user-123" {
		t.Errorf("GetSubject() = %q", r.GetSubject())
	}
	if r.GetClientID() != "client-456" {
		t.Errorf("GetClientID() = %q", r.GetClientID())
	}
	if len(r.GetScopes()) != 2 {
		t.Errorf("GetScopes() len = %d", len(r.GetScopes()))
	}
	if r.GetAudience()[0] != "client-456" {
		t.Errorf("GetAudience() = %v", r.GetAudience())
	}
	if r.GetAMR() != nil {
		t.Errorf("GetAMR() = %v, want nil", r.GetAMR())
	}
}

func TestRefreshTokenRequest_SetCurrentScopes(t *testing.T) {
	r := &refreshTokenRequest{scopes: []string{"openid"}}
	r.SetCurrentScopes([]string{"openid", "email"})
	if len(r.GetScopes()) != 2 {
		t.Errorf("after SetCurrentScopes, GetScopes() len = %d, want 2", len(r.GetScopes()))
	}
}

func TestHashToken(t *testing.T) {
	token := "test-token-value"
	hash1 := hashToken(token)
	hash2 := hashToken(token)

	if hash1 != hash2 {
		t.Error("hashToken should be deterministic")
	}
	if hash1 == token {
		t.Error("hashToken should not return the original token")
	}
	if len(hash1) != 64 {
		t.Errorf("hashToken should return 64-char hex string, got %d chars", len(hash1))
	}
}

func TestHashToken_DifferentInputs(t *testing.T) {
	h1 := hashToken("token-a")
	h2 := hashToken("token-b")

	if h1 == h2 {
		t.Error("different tokens should produce different hashes")
	}
}

func TestHashToken_EmptyString(t *testing.T) {
	hash := hashToken("")
	if hash == "" {
		t.Error("hashToken of empty string should not be empty")
	}
	if len(hash) != 64 {
		t.Errorf("hashToken of empty string should still be 64 chars, got %d", len(hash))
	}
}
