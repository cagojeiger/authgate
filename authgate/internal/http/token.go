package http

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"authgate/internal/domain"
	"github.com/google/uuid"
)

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeTokenError(w, "invalid_request", "Failed to parse form")
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if grantType != "authorization_code" && grantType != "refresh_token" && grantType != "urn:ietf:params:oauth:grant-type:device_code" {
		s.writeTokenError(w, "unsupported_grant_type", "Unsupported grant type")
		return
	}

	if clientID == "" {
		s.writeTokenError(w, "invalid_request", "client_id is required")
		return
	}

	ctx := r.Context()

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r, ctx, clientID, clientSecret)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r, ctx, clientID, clientSecret)
	case "urn:ietf:params:oauth:grant-type:device_code":
		s.handleDeviceCodeGrant(w, r, ctx, clientID, clientSecret)
	}
}

func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, clientSecret string) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" || redirectURI == "" || codeVerifier == "" {
		s.writeTokenError(w, "invalid_request", "code, redirect_uri, and code_verifier are required")
		return
	}

	authCode, err := s.store.GetAuthCode(ctx, code)
	if err != nil {
		s.writeTokenError(w, "invalid_grant", "Invalid or expired authorization code")
		return
	}

	if authCode.ClientID != clientID || authCode.RedirectURI != redirectURI {
		s.writeTokenError(w, "invalid_grant", "Client or redirect mismatch")
		return
	}

	expectedChallenge := base64.RawURLEncoding.EncodeToString(domain.SHA256Sum(codeVerifier))
	if subtle.ConstantTimeCompare([]byte(authCode.Challenge), []byte(expectedChallenge)) != 1 {
		s.writeTokenError(w, "invalid_grant", "PKCE verification failed")
		return
	}

	if err := s.store.MarkAuthCodeUsed(ctx, authCode.ID); err != nil {
		s.writeTokenError(w, "server_error", "Failed to mark code used")
		return
	}

	user, err := s.store.GetUserByID(ctx, authCode.UserID)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to get user")
		return
	}

	accessToken, err := s.tokens.GenerateAccessToken(
		user.ID, authCode.SessionID, clientID,
		user.PrimaryEmail, user.EmailVerified, user.Name, user.Name,
		authCode.Scopes,
	)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to generate access token")
		return
	}

	var idToken string
	if domain.ContainsScope(authCode.Scopes, "openid") {
		idToken, _ = s.tokens.GenerateIDToken(
			user.ID, clientID, user.PrimaryEmail, user.EmailVerified,
			user.Name, user.Name, authCode.Nonce,
		)
	}

	refreshToken := s.tokens.GenerateRefreshToken()
	_, err = s.store.CreateRefreshToken(ctx, refreshToken, user.ID, authCode.SessionID, clientID, authCode.Scopes, s.config.RefreshTokenTTL)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to create refresh token")
		return
	}

	response := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    s.config.AccessTokenTTL,
		"refresh_token": refreshToken,
		"scope":         strings.Join(authCode.Scopes, " "),
	}

	if idToken != "" {
		response["id_token"] = idToken
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, clientSecret string) {
	refreshToken := r.FormValue("refresh_token")

	if refreshToken == "" {
		s.writeTokenError(w, "invalid_request", "refresh_token is required")
		return
	}

	rt, err := s.store.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		s.writeTokenError(w, "invalid_grant", "Invalid or expired refresh token")
		return
	}

	if rt.ClientID != clientID {
		s.writeTokenError(w, "invalid_grant", "Client mismatch")
		return
	}

	user, err := s.store.GetUserByID(ctx, rt.UserID)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to get user")
		return
	}

	accessToken, err := s.tokens.GenerateAccessToken(
		user.ID, rt.SessionID, clientID,
		user.PrimaryEmail, user.EmailVerified, user.Name, user.Name,
		rt.Scopes,
	)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to generate access token")
		return
	}

	newRefreshToken := s.tokens.GenerateRefreshToken()
	_, err = s.store.RotateRefreshToken(ctx, rt.ID, newRefreshToken, s.config.RefreshTokenTTL)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to rotate refresh token")
		return
	}

	response := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    s.config.AccessTokenTTL,
		"refresh_token": newRefreshToken,
		"scope":         strings.Join(rt.Scopes, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, clientSecret string) {
	deviceCode := r.FormValue("device_code")

	if deviceCode == "" {
		s.writeTokenError(w, "invalid_request", "device_code is required")
		return
	}

	deviceReqMutex.Lock()
	deviceReq, exists := deviceCodes[deviceCode]
	if exists {
		deviceReq.LastPolledAt = time.Now()
	}
	deviceReqMutex.Unlock()

	if !exists || time.Now().After(deviceReq.ExpiresAt) {
		s.writeTokenError(w, "expired_token", "Device code has expired")
		return
	}

	if deviceReq.ClientID != clientID {
		s.writeTokenError(w, "invalid_grant", "Client mismatch")
		return
	}

	switch deviceReq.Status {
	case "pending":
		s.writeTokenError(w, "authorization_pending", "Authorization pending")
		return
	case "denied":
		s.writeTokenError(w, "access_denied", "User denied access")
		return
	case "approved":
		// Continue to generate tokens
	default:
		s.writeTokenError(w, "authorization_pending", "Authorization pending")
		return
	}

	// Check if we have user info
	if deviceReq.UserID == uuid.Nil {
		s.writeTokenError(w, "authorization_pending", "Authorization pending")
		return
	}

	user, err := s.store.GetUserByID(ctx, deviceReq.UserID)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to get user")
		return
	}

	scopes := strings.Split(deviceReq.Scope, " ")
	accessToken, err := s.tokens.GenerateAccessToken(
		user.ID, deviceReq.SessionID, clientID,
		user.PrimaryEmail, user.EmailVerified, user.Name, user.Name,
		scopes,
	)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to generate access token")
		return
	}

	var idToken string
	if domain.ContainsScope(scopes, "openid") {
		idToken, _ = s.tokens.GenerateIDToken(
			user.ID, clientID, user.PrimaryEmail, user.EmailVerified,
			user.Name, user.Name, "",
		)
	}

	refreshToken := s.tokens.GenerateRefreshToken()
	_, err = s.store.CreateRefreshToken(ctx, refreshToken, user.ID, deviceReq.SessionID, clientID, scopes, s.config.RefreshTokenTTL)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to create refresh token")
		return
	}

	// Clean up device code
	deviceReqMutex.Lock()
	delete(deviceCodes, deviceCode)
	deviceReqMutex.Unlock()

	response := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    s.config.AccessTokenTTL,
		"refresh_token": refreshToken,
		"scope":         deviceReq.Scope,
	}

	if idToken != "" {
		response["id_token"] = idToken
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	postLogoutURI := r.URL.Query().Get("post_logout_redirect_uri")

	cookie, err := r.Cookie("authgate_session")
	if err == nil && cookie.Value != "" {
		sessionID, _ := uuid.Parse(cookie.Value)
		if sessionID != uuid.Nil {
			s.store.RevokeSession(r.Context(), sessionID)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "authgate_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	if postLogoutURI == "" {
		postLogoutURI = s.config.BaseURL + "/logged-out"
	}

	http.Redirect(w, r, postLogoutURI, http.StatusFound)
}

func (s *Server) writeTokenError(w http.ResponseWriter, errorCode, description string) {
	w.WriteHeader(http.StatusBadRequest)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}
