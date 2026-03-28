package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Manager struct {
	signingKey interface{}
	publicKey  interface{}
	keyID      string
	issuer     string
	accessTTL  time.Duration
}

func NewManager(issuer string, accessTTLSeconds int) (*Manager, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &Manager{
		signingKey: key,
		publicKey:  &key.PublicKey,
		keyID:      "key-1",
		issuer:     issuer,
		accessTTL:  time.Duration(accessTTLSeconds) * time.Second,
	}, nil
}

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Scope             string `json:"scope,omitempty"`
	SessionID         string `json:"sid,omitempty"`
}

func (m *Manager) GenerateAccessToken(userID uuid.UUID, sessionID uuid.UUID, clientID string, email string, emailVerified bool, name, preferredUsername string, scopes []string) (string, error) {
	now := time.Now()

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		Email:             email,
		EmailVerified:     emailVerified,
		Name:              name,
		PreferredUsername: preferredUsername,
		Scope:             joinScopes(scopes),
		SessionID:         sessionID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.keyID

	return token.SignedString(m.signingKey)
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
}

func (m *Manager) GenerateIDToken(userID uuid.UUID, clientID, email string, emailVerified bool, name, preferredUsername, nonce string) (string, error) {
	now := time.Now()

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Email:             email,
		EmailVerified:     emailVerified,
		Name:              name,
		PreferredUsername: preferredUsername,
		Nonce:             nonce,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.keyID

	return token.SignedString(m.signingKey)
}

func (m *Manager) GenerateRefreshToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (m *Manager) GetJWKS() map[string]interface{} {
	rsakey := m.publicKey.(*rsa.PublicKey)
	n := base64.RawURLEncoding.EncodeToString(rsakey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsakey.E)).Bytes())

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": m.keyID,
				"alg": "RS256",
				"n":   n,
				"e":   e,
			},
		},
	}
}

func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}
