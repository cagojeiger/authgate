package op

import (
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	zop "github.com/zitadel/oidc/v3/pkg/op"
)

func TestClient_Interface(t *testing.T) {
	var _ zop.Client = &Client{}
}

func TestClient_InterfaceContract(t *testing.T) {
	c := &Client{
		ID:             "test-client",
		ClientType:     "confidential",
		Name:           "Test App",
		RedirectURIs_:  []string{"http://localhost/cb"},
		AllowedScopes_: []string{"openid", "profile", "email"},
	}

	if c.GetID() != "test-client" {
		t.Errorf("GetID() = %q", c.GetID())
	}
	if c.LoginURL("req-1") != "/login?authRequestID=req-1" {
		t.Errorf("LoginURL() = %q", c.LoginURL("req-1"))
	}
	if c.AuthMethod() != oidc.AuthMethodPost {
		t.Errorf("AuthMethod(confidential) = %v, want Post", c.AuthMethod())
	}
	if c.AccessTokenType() != zop.AccessTokenTypeJWT {
		t.Errorf("AccessTokenType() = %v, want JWT", c.AccessTokenType())
	}
	if c.ApplicationType() != zop.ApplicationTypeWeb {
		t.Errorf("ApplicationType() = %v, want Web", c.ApplicationType())
	}
	if len(c.GrantTypes()) != 3 {
		t.Errorf("GrantTypes() len = %d, want 3", len(c.GrantTypes()))
	}
	if len(c.ResponseTypes()) != 1 || c.ResponseTypes()[0] != oidc.ResponseTypeCode {
		t.Errorf("ResponseTypes() = %v, want [code]", c.ResponseTypes())
	}
	if len(c.RedirectURIs()) != 1 {
		t.Errorf("RedirectURIs() len = %d", len(c.RedirectURIs()))
	}
	if c.IDTokenLifetime() != time.Hour {
		t.Errorf("IDTokenLifetime() = %v", c.IDTokenLifetime())
	}
	if c.ClockSkew() != 0 {
		t.Errorf("ClockSkew() = %v", c.ClockSkew())
	}
	if c.DevMode() != false {
		t.Error("DevMode() should default to false")
	}
}

func TestClient_AuthMethod_Public(t *testing.T) {
	c := &Client{ClientType: "public"}
	if c.AuthMethod() != oidc.AuthMethodNone {
		t.Errorf("AuthMethod(public) = %v, want None", c.AuthMethod())
	}
}

func TestClient_IsScopeAllowed(t *testing.T) {
	c := &Client{AllowedScopes_: []string{"openid", "profile", "email"}}
	tests := []struct {
		scope string
		want  bool
	}{
		{"openid", true}, {"profile", true}, {"email", true},
		{"admin", false}, {"", false},
	}
	for _, tt := range tests {
		if got := c.IsScopeAllowed(tt.scope); got != tt.want {
			t.Errorf("IsScopeAllowed(%q) = %v, want %v", tt.scope, got, tt.want)
		}
	}
}
