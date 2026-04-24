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

type ConnectionView struct {
	ClientID string   `json:"client_id"`
	Name     string   `json:"name"`
	URL      string   `json:"url,omitempty"`
	Scopes   []string `json:"scopes"`
	LastUsed string   `json:"last_used"`
}

type consoleAuth struct {
	user     *storage.User
	clientID string
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
			return &consoleAuth{user: user}, nil
		}
	}
	if authHeader != "" {
		user, clientID, err := s.store.ValidateBearerTokenWithClientID(ctx, authHeader)
		if err != nil {
			return nil, err
		}
		return &consoleAuth{user: user, clientID: clientID}, nil
	}
	return nil, errors.New("unauthenticated")
}

func (s *ConsoleService) ListClients(ctx context.Context, sessionID, authHeader string) *ClientsResult {
	user, err := s.resolveUser(ctx, sessionID, authHeader)
	if err != nil {
		return &ClientsResult{ErrorCode: http.StatusUnauthorized}
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
		return &ConnectionsResult{ErrorCode: http.StatusUnauthorized}
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

func (s *ConsoleService) RevokeConnection(ctx context.Context, sessionID, authHeader, clientID string) *RevokeConnectionResult {
	auth, err := s.resolveAuth(ctx, sessionID, authHeader)
	if err != nil {
		return &RevokeConnectionResult{ErrorCode: http.StatusUnauthorized}
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
