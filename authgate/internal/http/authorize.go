package http

import (
	"net/http"
	"strings"
	"time"

	"authgate/internal/pages"
	"authgate/internal/storage"
	"github.com/google/uuid"
)

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	if responseType != "code" {
		s.redirectError(w, r, redirectURI, "unsupported_response_type", "response_type must be code", state)
		return
	}

	if clientID == "" || redirectURI == "" || state == "" || codeChallenge == "" {
		s.redirectError(w, r, redirectURI, "invalid_request", "missing required parameters", state)
		return
	}

	if codeChallengeMethod != "S256" {
		s.redirectError(w, r, redirectURI, "invalid_request", "PKCE S256 required", state)
		return
	}

	allowed := false
	for _, uri := range s.config.AllowedRedirectURIs() {
		if uri == redirectURI {
			allowed = true
			break
		}
	}
	if !allowed {
		s.redirectError(w, r, redirectURI, "invalid_request", "redirect_uri not allowed", state)
		return
	}

	if scope == "" {
		scope = "openid profile email"
	}

	cookie, err := r.Cookie("authgate_session")
	if err == nil && cookie.Value != "" {
		sessionID, _ := uuid.Parse(cookie.Value)
		if sessionID != uuid.Nil {
			session, err := s.store.GetSession(r.Context(), sessionID)
			if err == nil && session != nil {
				user, err := s.store.GetUserByID(r.Context(), session.UserID)
				if err == nil && user != nil {
					s.showConsentPage(w, r, user, session, clientID, redirectURI, scope, state, codeChallenge, q.Get("nonce"))
					return
				}
			}
		}
	}

	reqID := generateCode()
	authReqMutex.Lock()
	authRequests[reqID] = &AuthRequest{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		State:       state,
		Challenge:   codeChallenge,
		Nonce:       q.Get("nonce"),
		CreatedAt:   time.Now(),
	}
	authReqMutex.Unlock()

	upstreamState := generateState(reqID, clientID, redirectURI, scope, codeChallenge, q.Get("nonce"))
	loginURL := s.upstream.GetAuthorizeURL(upstreamState, "", s.config.PublicURL+"/oauth/callback")
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (s *Server) showConsentPage(w http.ResponseWriter, r *http.Request, user *storage.User, session *storage.Session, clientID, redirectURI, scope, state, challenge, nonce string) {
	reqID := generateCode()
	authReqMutex.Lock()
	authRequests[reqID] = &AuthRequest{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		State:       state,
		Challenge:   challenge,
		Nonce:       nonce,
		UserID:      user.ID,
		SessionID:   session.ID,
		CreatedAt:   time.Now(),
	}
	authReqMutex.Unlock()

	scopes := strings.Split(scope, " ")
	data := struct {
		Title       string
		ClientName  string
		ClientID    string
		UserName    string
		UserEmail   string
		Scopes      []string
		State       string
		RedirectURI string
		ReqID       string
	}{
		Title:       "Authorize Application",
		ClientName:  clientID,
		ClientID:    clientID,
		UserName:    user.Name,
		UserEmail:   user.PrimaryEmail,
		Scopes:      scopes,
		State:       state,
		RedirectURI: redirectURI,
		ReqID:       reqID,
	}

	s.pages.RenderConsent(w, pages.ConsentData{
		Title:       data.Title,
		ClientName:  data.ClientName,
		ClientID:    data.ClientID,
		UserName:    data.UserName,
		UserEmail:   data.UserEmail,
		Scopes:      data.Scopes,
		State:       data.State,
		RedirectURI: data.RedirectURI,
		ReqID:       data.ReqID,
	})
}
