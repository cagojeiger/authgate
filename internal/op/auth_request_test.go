package op

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	zop "github.com/zitadel/oidc/v3/pkg/op"
)

func TestAuthRequest_Interface(t *testing.T) {
	var _ zop.AuthRequest = &AuthRequest{}
}

func TestAuthRequest_InterfaceContract(t *testing.T) {
	now := time.Now()
	id := uuid.New()
	ar := &AuthRequest{
		ID: id, ClientID: "client-1", RedirectURI: "http://localhost/cb",
		Scopes: []string{"openid", "profile"}, State: "state-1", Nonce: "nonce-1",
		Subject: "user-1", AuthTime: now, Done_: true,
	}

	if ar.GetID() != id.String() {
		t.Errorf("GetID() = %q", ar.GetID())
	}
	if ar.GetClientID() != "client-1" {
		t.Errorf("GetClientID() = %q", ar.GetClientID())
	}
	if ar.GetRedirectURI() != "http://localhost/cb" {
		t.Errorf("GetRedirectURI() = %q", ar.GetRedirectURI())
	}
	if len(ar.GetScopes()) != 2 {
		t.Errorf("GetScopes() len = %d", len(ar.GetScopes()))
	}
	if ar.GetState() != "state-1" {
		t.Errorf("GetState() = %q", ar.GetState())
	}
	if ar.GetSubject() != "user-1" {
		t.Errorf("GetSubject() = %q", ar.GetSubject())
	}
	if !ar.Done() {
		t.Error("Done() = false, want true")
	}
	if ar.GetResponseType() != oidc.ResponseTypeCode {
		t.Errorf("GetResponseType() = %v", ar.GetResponseType())
	}
	if ar.GetAudience()[0] != "client-1" {
		t.Errorf("GetAudience() = %v", ar.GetAudience())
	}
}

func TestAuthRequest_CodeChallenge(t *testing.T) {
	// Empty — should be nil
	ar := &AuthRequest{}
	if ar.GetCodeChallenge() != nil {
		t.Error("empty challenge should return nil")
	}

	// With value — should return struct
	ar.CodeChallenge = "challenge-value"
	ar.CodeChallengeMethod = "S256"
	cc := ar.GetCodeChallenge()
	if cc == nil || cc.Challenge != "challenge-value" || cc.Method != "S256" {
		t.Errorf("GetCodeChallenge() = %+v", cc)
	}
}

func TestAuthRequest_Done_Toggle(t *testing.T) {
	ar := &AuthRequest{Done_: false}
	if ar.Done() {
		t.Error("should be false")
	}
	ar.Done_ = true
	if !ar.Done() {
		t.Error("should be true")
	}
}
