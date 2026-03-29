package op

import (
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AuthRequest struct {
	ID                  uuid.UUID
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Subject             string
	AuthTime            time.Time
	Done_               bool
	Code                string
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

func (a *AuthRequest) GetID() string            { return a.ID.String() }
func (a *AuthRequest) GetACR() string            { return "" }
func (a *AuthRequest) GetAMR() []string          { return nil }
func (a *AuthRequest) GetAudience() []string     { return []string{a.ClientID} }
func (a *AuthRequest) GetAuthTime() time.Time    { return a.AuthTime }
func (a *AuthRequest) GetClientID() string       { return a.ClientID }
func (a *AuthRequest) GetNonce() string          { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string    { return a.RedirectURI }
func (a *AuthRequest) GetResponseType() oidc.ResponseType { return oidc.ResponseTypeCode }
func (a *AuthRequest) GetResponseMode() oidc.ResponseMode { return "" }
func (a *AuthRequest) GetScopes() []string       { return a.Scopes }
func (a *AuthRequest) GetState() string          { return a.State }
func (a *AuthRequest) GetSubject() string        { return a.Subject }
func (a *AuthRequest) Done() bool                { return a.Done_ }

func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: a.CodeChallenge,
		Method:    oidc.CodeChallengeMethod(a.CodeChallengeMethod),
	}
}
