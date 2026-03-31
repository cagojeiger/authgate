package main

import (
	"context"
	"net/http"
)

type contextKey string

const (
	claimsKey  contextKey = "claims"
	sessionKey contextKey = "session"
)

func RequireAuth(verifier *JWKSVerifier, auth *AuthHandler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("access_token")
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			token := cookie.Value

			// Quick expiry check — try refresh before full verification
			if QuickExpired(token) {
				newToken, ok := auth.RefreshAccessToken(w, r)
				if !ok {
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}
				token = newToken
			}

			// Full JWT verification
			claims, err := verifier.VerifyToken(r.Context(), token)
			if err != nil {
				newToken, ok := auth.RefreshAccessToken(w, r)
				if !ok {
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}
				claims, err = verifier.VerifyToken(r.Context(), newToken)
				if err != nil {
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)

			// Attach session if available (for email/name from userinfo)
			if sidCookie, err := r.Cookie("sid"); err == nil {
				if sess := auth.sessions.Get(sidCookie.Value); sess != nil {
					ctx = context.WithValue(ctx, sessionKey, sess)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetClaims(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

func GetSession(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey).(*Session)
	return s
}
