package service

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/kangheeyong/authgate/internal/storage"
)

type ConsoleService struct {
	store ConsoleStore
}

type ConsoleStore interface {
	GetValidSession(ctx context.Context, sessionID string) (*storage.User, error)
	ValidateBearerToken(ctx context.Context, authHeader string) (*storage.User, error)
	ValidateBearerTokenWithClientID(ctx context.Context, authHeader string) (*storage.User, string, error)
	ListAllClients() []storage.ClientView
	GetActiveConnections(ctx context.Context, userID string) ([]storage.ConnectionTokenInfo, error)
	RevokeConnection(ctx context.Context, userID, clientID string) error
	GetActiveSessions(ctx context.Context, userID string) ([]storage.SessionInfo, error)
	RevokeSession(ctx context.Context, userID, sessionID string) error
	RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) error
	GetAuditLog(ctx context.Context, userID string, limit, offset int) (*storage.AuditLogPage, error)
	AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error
}

func NewConsoleService(store ConsoleStore) *ConsoleService {
	return &ConsoleService{store: store}
}

type ClientsResult struct {
	Clients   []storage.ClientView
	ErrorCode int
}

type ConnectionsResult struct {
	Connections []ConnectionView
	ErrorCode   int
}

type RevokeConnectionResult struct {
	ErrorCode int
}

type SessionsResult struct {
	Sessions  []SessionView
	ErrorCode int
}

type RevokeSessionResult struct {
	ErrorCode int
}

type RevokeOtherSessionsResult struct {
	ErrorCode int
}

type AuditLogResult struct {
	Events    []AuditEventView
	Page      int
	Limit     int
	Total     int
	ErrorCode int
}

type ConnectionView struct {
	ClientID string   `json:"client_id"`
	Name     string   `json:"name"`
	URL      string   `json:"url,omitempty"`
	Scopes   []string `json:"scopes"`
	LastUsed string   `json:"last_used"`
}

type SessionView struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expires_at"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	CreatedAt string `json:"created_at"`
	IsCurrent bool   `json:"is_current"`
}

type AuditEventView struct {
	ID        int64          `json:"id"`
	EventType string         `json:"event_type"`
	IPAddress string         `json:"ip_address"`
	UserAgent string         `json:"user_agent"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt string         `json:"created_at"`
}

type consoleAuth struct {
	user      *storage.User
	clientID  string
	sessionID string
}

type consoleAuthError struct {
	statusCode int
	err        error
}

func (e *consoleAuthError) Error() string {
	return e.err.Error()
}

func (e *consoleAuthError) Unwrap() error {
	return e.err
}

func consoleAuthErrorCode(err error) int {
	var authErr *consoleAuthError
	if errors.As(err, &authErr) {
		return authErr.statusCode
	}
	return http.StatusUnauthorized
}

// resolveUser tries session cookie first, then Bearer token.
func (s *ConsoleService) resolveUser(ctx context.Context, sessionID, authHeader string) (*storage.User, error) {
	auth, err := s.resolveAuth(ctx, sessionID, authHeader)
	if err != nil {
		return nil, err
	}
	return auth.user, nil
}

func (s *ConsoleService) resolveAuth(ctx context.Context, sessionID, authHeader string) (*consoleAuth, error) {
	if sessionID != "" {
		user, err := s.store.GetValidSession(ctx, sessionID)
		if err == nil {
			return &consoleAuth{user: user, sessionID: sessionID}, nil
		}
		if !errors.Is(err, storage.ErrNotFound) {
			return nil, &consoleAuthError{statusCode: http.StatusInternalServerError, err: err}
		}
	}
	if authHeader != "" {
		user, clientID, err := s.store.ValidateBearerTokenWithClientID(ctx, authHeader)
		if err != nil {
			return nil, &consoleAuthError{statusCode: http.StatusUnauthorized, err: err}
		}
		return &consoleAuth{user: user, clientID: clientID}, nil
	}
	return nil, &consoleAuthError{statusCode: http.StatusUnauthorized, err: errors.New("unauthenticated")}
}

func (s *ConsoleService) ListClients(ctx context.Context, sessionID, authHeader string) *ClientsResult {
	user, err := s.resolveUser(ctx, sessionID, authHeader)
	if err != nil {
		return &ClientsResult{ErrorCode: consoleAuthErrorCode(err)}
	}
	if CheckAccess(user.Status, "browser") != AccessAllow {
		return &ClientsResult{ErrorCode: http.StatusForbidden}
	}
	clients := s.store.ListAllClients()
	if clients == nil {
		clients = []storage.ClientView{}
	}
	return &ClientsResult{Clients: clients}
}

func (s *ConsoleService) ListConnections(ctx context.Context, sessionID, authHeader string) *ConnectionsResult {
	user, err := s.resolveUser(ctx, sessionID, authHeader)
	if err != nil {
		return &ConnectionsResult{ErrorCode: consoleAuthErrorCode(err)}
	}
	if CheckAccess(user.Status, "browser") != AccessAllow {
		return &ConnectionsResult{ErrorCode: http.StatusForbidden}
	}

	connections, err := s.store.GetActiveConnections(ctx, user.ID)
	if err != nil {
		return &ConnectionsResult{ErrorCode: http.StatusInternalServerError}
	}

	allClients := s.store.ListAllClients()
	type clientMeta struct{ name, url string }
	metaByID := make(map[string]clientMeta, len(allClients))
	for _, c := range allClients {
		metaByID[c.ClientID] = clientMeta{name: c.Name, url: c.URL}
	}

	views := make([]ConnectionView, 0, len(connections))
	for _, conn := range connections {
		meta := metaByID[conn.ClientID]
		name := meta.name
		if name == "" {
			name = conn.ClientID
		}
		lastUsed := ""
		if conn.LastUsed != nil {
			lastUsed = conn.LastUsed.UTC().Format(time.RFC3339)
		}
		views = append(views, ConnectionView{
			ClientID: conn.ClientID,
			Name:     name,
			URL:      meta.url,
			Scopes:   append([]string(nil), conn.Scopes...),
			LastUsed: lastUsed,
		})
	}
	return &ConnectionsResult{Connections: views}
}

func (s *ConsoleService) ListSessions(ctx context.Context, sessionID, authHeader string) *SessionsResult {
	auth, err := s.resolveAuth(ctx, sessionID, authHeader)
	if err != nil {
		return &SessionsResult{ErrorCode: consoleAuthErrorCode(err)}
	}
	if CheckAccess(auth.user.Status, "browser") != AccessAllow {
		return &SessionsResult{ErrorCode: http.StatusForbidden}
	}

	sessions, err := s.store.GetActiveSessions(ctx, auth.user.ID)
	if err != nil {
		return &SessionsResult{ErrorCode: http.StatusInternalServerError}
	}
	views := make([]SessionView, 0, len(sessions))
	for _, sess := range sessions {
		createdAt := ""
		if sess.CreatedAt != nil {
			createdAt = sess.CreatedAt.UTC().Format(time.RFC3339)
		}
		views = append(views, SessionView{
			ID:        sess.ID,
			ExpiresAt: sess.ExpiresAt.UTC().Format(time.RFC3339),
			IPAddress: sess.IPAddress,
			UserAgent: sess.UserAgent,
			CreatedAt: createdAt,
			IsCurrent: auth.sessionID != "" && auth.sessionID == sess.ID,
		})
	}
	return &SessionsResult{Sessions: views}
}

func (s *ConsoleService) RevokeConnection(ctx context.Context, sessionID, authHeader, clientID string) *RevokeConnectionResult {
	auth, err := s.resolveAuth(ctx, sessionID, authHeader)
	if err != nil {
		return &RevokeConnectionResult{ErrorCode: consoleAuthErrorCode(err)}
	}
	if CheckAccess(auth.user.Status, "browser") != AccessAllow {
		return &RevokeConnectionResult{ErrorCode: http.StatusForbidden}
	}
	if clientID == "" {
		return &RevokeConnectionResult{ErrorCode: http.StatusBadRequest}
	}
	if auth.clientID != "" && auth.clientID == clientID {
		return &RevokeConnectionResult{ErrorCode: http.StatusBadRequest}
	}
	if err := s.store.RevokeConnection(ctx, auth.user.ID, clientID); err != nil {
		return &RevokeConnectionResult{ErrorCode: http.StatusInternalServerError}
	}
	s.store.AuditLog(ctx, &auth.user.ID, "auth.connection_revoked", "", "", map[string]any{"client_id": clientID})
	return &RevokeConnectionResult{}
}

func (s *ConsoleService) RevokeSession(ctx context.Context, sessionID, authHeader, revokeSessionID string) *RevokeSessionResult {
	auth, err := s.resolveAuth(ctx, sessionID, authHeader)
	if err != nil {
		return &RevokeSessionResult{ErrorCode: consoleAuthErrorCode(err)}
	}
	if CheckAccess(auth.user.Status, "browser") != AccessAllow {
		return &RevokeSessionResult{ErrorCode: http.StatusForbidden}
	}
	if revokeSessionID == "" {
		return &RevokeSessionResult{ErrorCode: http.StatusBadRequest}
	}
	if err := s.store.RevokeSession(ctx, auth.user.ID, revokeSessionID); err != nil {
		return &RevokeSessionResult{ErrorCode: http.StatusInternalServerError}
	}
	s.store.AuditLog(ctx, &auth.user.ID, "auth.session_revoked", "", "", map[string]any{"session_id": revokeSessionID})
	return &RevokeSessionResult{}
}

func (s *ConsoleService) RevokeOtherSessions(ctx context.Context, sessionID, authHeader string) *RevokeOtherSessionsResult {
	auth, err := s.resolveAuth(ctx, sessionID, authHeader)
	if err != nil {
		return &RevokeOtherSessionsResult{ErrorCode: consoleAuthErrorCode(err)}
	}
	if CheckAccess(auth.user.Status, "browser") != AccessAllow {
		return &RevokeOtherSessionsResult{ErrorCode: http.StatusForbidden}
	}
	if auth.sessionID == "" {
		return &RevokeOtherSessionsResult{ErrorCode: http.StatusBadRequest}
	}
	if err := s.store.RevokeOtherSessions(ctx, auth.user.ID, auth.sessionID); err != nil {
		return &RevokeOtherSessionsResult{ErrorCode: http.StatusInternalServerError}
	}
	return &RevokeOtherSessionsResult{}
}

func (s *ConsoleService) GetAuditLog(ctx context.Context, sessionID, authHeader string, page, limit int) *AuditLogResult {
	user, err := s.resolveUser(ctx, sessionID, authHeader)
	if err != nil {
		return &AuditLogResult{ErrorCode: consoleAuthErrorCode(err)}
	}
	if CheckAccess(user.Status, "browser") != AccessAllow {
		return &AuditLogResult{ErrorCode: http.StatusForbidden}
	}
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	auditPage, err := s.store.GetAuditLog(ctx, user.ID, limit, (page-1)*limit)
	if err != nil {
		return &AuditLogResult{ErrorCode: http.StatusInternalServerError}
	}
	events := make([]AuditEventView, 0, len(auditPage.Events))
	for _, event := range auditPage.Events {
		metadata := event.Metadata
		if metadata == nil {
			metadata = map[string]any{}
		}
		events = append(events, AuditEventView{
			ID:        event.ID,
			EventType: event.EventType,
			IPAddress: event.IPAddress,
			UserAgent: event.UserAgent,
			Metadata:  metadata,
			CreatedAt: event.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	return &AuditLogResult{
		Events: events,
		Page:   page,
		Limit:  limit,
		Total:  auditPage.Total,
	}
}
