package login

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"authgate/internal/storage"
)

// sessionGetter is the subset of UserStore needed by getSessionUser.
type sessionGetter interface {
	GetSession(ctx context.Context, id uuid.UUID) (*storage.Session, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*storage.User, error)
}

// writeError writes a consistent JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

// getSessionUser extracts the authenticated user from the session cookie.
// Returns nil, nil, nil if no valid session exists (not an error).
func getSessionUser(users sessionGetter, r *http.Request) (*storage.Session, *storage.User, error) {
	cookie, err := r.Cookie("authgate_session")
	if err != nil {
		return nil, nil, nil
	}

	sessionID, err := uuid.Parse(cookie.Value)
	if err != nil {
		slog.Warn("auth.invalid_session", "reason", "malformed cookie", "ip", r.RemoteAddr)
		return nil, nil, nil
	}

	session, err := users.GetSession(r.Context(), sessionID)
	if err != nil {
		return nil, nil, nil
	}

	user, err := users.GetUserByID(r.Context(), session.UserID)
	if err != nil {
		return nil, nil, err
	}

	return session, user, nil
}
