package http

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	errorCode := q.Get("error")

	if errorCode != "" {
		http.Error(w, "Upstream error: "+errorCode, http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	reqID, _, _, _, _, _ := parseState(state)

	userInfo, err := s.upstream.ExchangeCode(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	user, err := s.store.GetUserByProviderIdentity(ctx, s.config.UpstreamProvider, userInfo.ProviderUserID)
	if err != nil {
		user, err = s.store.CreateUser(ctx, userInfo.Email, userInfo.Name, userInfo.Picture, userInfo.EmailVerified)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		err = s.store.CreateUserIdentity(ctx, user.ID, s.config.UpstreamProvider, userInfo.ProviderUserID, userInfo.Email, nil)
		if err != nil {
			http.Error(w, "Failed to create identity", http.StatusInternalServerError)
			return
		}
	}

	session, err := s.store.CreateSession(ctx, user.ID, s.config.SessionTTL)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "authgate_session",
		Value:    session.ID.String(),
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   s.config.SessionTTL,
	})

	authReqMutex.Lock()
	authReq, exists := authRequests[reqID]
	if exists && authReq.UserID == uuid.Nil {
		authReq.UserID = user.ID
		authReq.SessionID = session.ID
		authReqMutex.Unlock()
		s.showConsentPage(w, r, user, session, authReq.ClientID, authReq.RedirectURI, authReq.Scope, authReq.State, authReq.Challenge, authReq.Nonce)
		return
	}
	authReqMutex.Unlock()

	authCode := generateCode()
	scopes := strings.Split("openid profile email", " ")

	_, err = s.store.CreateAuthCode(ctx, authCode, "service-a-web", user.ID, session.ID, s.config.PublicURL+"/oauth/callback", scopes, "", "", state)
	if err != nil {
		http.Error(w, "Failed to create auth code", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, s.config.PublicURL+"/oauth/callback?code="+authCode+"&state="+state, http.StatusFound)
}
