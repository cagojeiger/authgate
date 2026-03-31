package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type Claims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   any    `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type JWKSVerifier struct {
	jwksURL   string
	issuer    string
	clientID  string
	mu        sync.RWMutex
	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
	client    *http.Client
}

func NewJWKSVerifier(jwksURL, issuer, clientID string) *JWKSVerifier {
	return &JWKSVerifier{
		jwksURL:  jwksURL,
		issuer:   issuer,
		clientID: clientID,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (v *JWKSVerifier) fetchKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return err
	}
	v.mu.Lock()
	v.keys = &keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *JWKSVerifier) getKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	v.mu.RLock()
	keys := v.keys
	age := time.Since(v.fetchedAt)
	v.mu.RUnlock()

	if keys == nil || age > 5*time.Minute {
		if err := v.fetchKeys(ctx); err != nil {
			if keys != nil {
				return keys, nil
			}
			return nil, err
		}
		v.mu.RLock()
		keys = v.keys
		v.mu.RUnlock()
	}
	return keys, nil
}

func (v *JWKSVerifier) VerifyToken(ctx context.Context, tokenString string) (*Claims, error) {
	sig, err := jose.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}

	keys, err := v.getKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("get jwks: %w", err)
	}

	kid := ""
	if len(sig.Signatures) > 0 {
		kid = sig.Signatures[0].Header.KeyID
	}

	matchedKeys := keys.Key(kid)
	if len(matchedKeys) == 0 {
		if err := v.fetchKeys(ctx); err != nil {
			return nil, fmt.Errorf("jwks refetch: %w", err)
		}
		v.mu.RLock()
		matchedKeys = v.keys.Key(kid)
		v.mu.RUnlock()
		if len(matchedKeys) == 0 {
			return nil, fmt.Errorf("no key found for kid %q", kid)
		}
	}

	payload, err := sig.Verify(matchedKeys[0])
	if err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	now := time.Now().Unix()
	if claims.Exp < now {
		return nil, fmt.Errorf("token expired")
	}
	if claims.Iss != v.issuer {
		return nil, fmt.Errorf("issuer mismatch: got %q want %q", claims.Iss, v.issuer)
	}
	if !v.checkAud(claims.Aud) {
		return nil, fmt.Errorf("audience mismatch")
	}

	return &claims, nil
}

func (v *JWKSVerifier) checkAud(aud any) bool {
	switch a := aud.(type) {
	case string:
		return a == v.clientID
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok && s == v.clientID {
				return true
			}
		}
	}
	return false
}

// QuickExpired checks if a JWT is expired without verifying the signature.
func QuickExpired(tokenString string) bool {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return true
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return true
	}
	return c.Exp < time.Now().Unix()
}
