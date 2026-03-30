package storage

import (
	"crypto/rsa"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// --- User ---

type User struct {
	ID                string
	Email             string
	EmailVerified     bool
	Name              string
	AvatarURL         *string
	Status            string
	TermsVersion      *string
	TermsAcceptedAt   *time.Time
	PrivacyVersion    *string
	PrivacyAcceptedAt *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// --- AuthRequest Model ---

type AuthRequestModel struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	Scopes              oidc.SpaceDelimitedArray
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Subject             *string
	AuthTime            *time.Time
	IsDone              bool
	Code                *string
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

func (a *AuthRequestModel) GetID() string                          { return a.ID }
func (a *AuthRequestModel) GetACR() string                        { return "" }
func (a *AuthRequestModel) GetAMR() []string                      { return nil }
func (a *AuthRequestModel) GetAudience() []string                 { return []string{a.ClientID} }
func (a *AuthRequestModel) GetClientID() string                   { return a.ClientID }
func (a *AuthRequestModel) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: a.CodeChallenge,
		Method:    oidc.CodeChallengeMethod(a.CodeChallengeMethod),
	}
}
func (a *AuthRequestModel) GetNonce() string        { return a.Nonce }
func (a *AuthRequestModel) GetRedirectURI() string  { return a.RedirectURI }
func (a *AuthRequestModel) GetResponseType() oidc.ResponseType { return oidc.ResponseTypeCode }
func (a *AuthRequestModel) GetResponseMode() oidc.ResponseMode { return "" }
func (a *AuthRequestModel) GetScopes() []string     { return a.Scopes }
func (a *AuthRequestModel) GetState() string        { return a.State }
func (a *AuthRequestModel) Done() bool              { return a.IsDone }

func (a *AuthRequestModel) GetAuthTime() time.Time {
	if a.AuthTime != nil {
		return *a.AuthTime
	}
	return time.Time{}
}

func (a *AuthRequestModel) GetSubject() string {
	if a.Subject != nil {
		return *a.Subject
	}
	return ""
}

// --- RefreshToken Model ---

type RefreshTokenModel struct {
	ID        string
	TokenHash string
	FamilyID  string
	UserID    string
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
	RevokedAt *time.Time
	UsedAt    *time.Time
}

func (r *RefreshTokenModel) GetAMR() []string              { return nil }
func (r *RefreshTokenModel) GetAudience() []string         { return []string{r.ClientID} }
func (r *RefreshTokenModel) GetAuthTime() time.Time        { return time.Time{} }
func (r *RefreshTokenModel) GetClientID() string           { return r.ClientID }
func (r *RefreshTokenModel) GetScopes() []string           { return r.Scopes }
func (r *RefreshTokenModel) GetSubject() string            { return r.UserID }
func (r *RefreshTokenModel) SetCurrentScopes(scopes []string) { r.Scopes = scopes }

// --- Client Model ---

type ClientModel struct {
	UUID                 string
	ID                   string
	SecretHash           *string
	Type                 string
	Name                 string
	RedirectURIList      []string
	AllowedScopeList     []string
	AllowedGrantTypeList []string
}

func (c *ClientModel) GetID() string                { return c.ID }
func (c *ClientModel) RedirectURIs() []string       { return c.RedirectURIList }
func (c *ClientModel) PostLogoutRedirectURIs() []string { return nil }
func (c *ClientModel) ApplicationType() op.ApplicationType {
	if c.Type == "confidential" {
		return op.ApplicationTypeWeb
	}
	return op.ApplicationTypeNative
}
func (c *ClientModel) AuthMethod() oidc.AuthMethod {
	if c.SecretHash != nil {
		return oidc.AuthMethodBasic
	}
	return oidc.AuthMethodNone
}
func (c *ClientModel) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *ClientModel) GrantTypes() []oidc.GrantType {
	types := make([]oidc.GrantType, 0, len(c.AllowedGrantTypeList))
	for _, gt := range c.AllowedGrantTypeList {
		types = append(types, oidc.GrantType(gt))
	}
	return types
}
func (c *ClientModel) LoginURL(authRequestID string) string {
	return "/login?authRequestID=" + authRequestID
}
func (c *ClientModel) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeJWT
}
func (c *ClientModel) IDTokenLifetime() time.Duration {
	return time.Hour
}
func (c *ClientModel) DevMode() bool { return false }
func (c *ClientModel) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *ClientModel) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *ClientModel) IsScopeAllowed(scope string) bool {
	for _, s := range c.AllowedScopeList {
		if s == scope {
			return true
		}
	}
	return false
}
func (c *ClientModel) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *ClientModel) ClockSkew() time.Duration             { return 0 }

// --- DeviceCode Model ---

type DeviceCodeModel struct {
	ID       string
	ClientID string
	Scopes   []string
	State    string
	Subject  *string
	ExpiresAt time.Time
	AuthTime  *time.Time
}

// --- Key Models ---

type signingKeyModel struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PrivateKey
}

func (k *signingKeyModel) SignatureAlgorithm() jose.SignatureAlgorithm { return k.algorithm }
func (k *signingKeyModel) Key() any                                    { return k.key }
func (k *signingKeyModel) ID() string                                  { return k.id }

type publicKeyModel struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PublicKey
}

func (k *publicKeyModel) ID() string                                  { return k.id }
func (k *publicKeyModel) Algorithm() jose.SignatureAlgorithm          { return k.algorithm }
func (k *publicKeyModel) Use() string                                 { return "sig" }
func (k *publicKeyModel) Key() any                                    { return k.key }
