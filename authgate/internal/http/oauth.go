package http

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Temporary storage for auth requests (in production, use Redis or DB)
var (
	authRequests = make(map[string]*AuthRequest)
	authReqMutex sync.RWMutex
)

type AuthRequest struct {
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	Challenge   string
	Nonce       string
	UserID      uuid.UUID
	SessionID   uuid.UUID
	CreatedAt   time.Time
}

func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, errorCode, description, state string) {
	if redirectURI == "" {
		http.Error(w, errorCode+": "+description, http.StatusBadRequest)
		return
	}

	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", errorCode)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) writeJSONError(w http.ResponseWriter, status int, errorCode, description string) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"error":"` + errorCode + `","error_description":"` + description + `"}`))
}
