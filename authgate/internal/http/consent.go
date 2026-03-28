package http

import (
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	reqID := r.FormValue("req_id")
	action := r.FormValue("action")

	authReqMutex.Lock()
	authReq, exists := authRequests[reqID]
	if exists {
		delete(authRequests, reqID)
	}
	authReqMutex.Unlock()

	if !exists {
		http.Error(w, "Invalid or expired request", http.StatusBadRequest)
		return
	}

	if action != "approve" {
		s.redirectError(w, r, authReq.RedirectURI, "access_denied", "User denied access", authReq.State)
		return
	}

	code := generateCode()
	scopes := strings.Split(authReq.Scope, " ")

	_, err := s.store.CreateAuthCode(r.Context(), code, authReq.ClientID, authReq.UserID, authReq.SessionID, authReq.RedirectURI, scopes, authReq.Challenge, authReq.Nonce, authReq.State)
	if err != nil {
		s.redirectError(w, r, authReq.RedirectURI, "server_error", "Failed to create auth code", authReq.State)
		return
	}

	redirectURL, _ := url.Parse(authReq.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", authReq.State)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
