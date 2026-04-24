package service

import (
	"context"
	"errors"
	"net/http"

	"github.com/kangheeyong/authgate/internal/storage"
)

type ConsoleService struct {
	store ConsoleStore
}

type ConsoleStore interface {
	GetValidSession(ctx context.Context, sessionID string) (*storage.User, error)
	ValidateBearerToken(ctx context.Context, authHeader string) (*storage.User, error)
	ListAllClients() []storage.ClientView
	GetActiveConnections(ctx context.Context, userID string) ([]string, error)
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

type ConnectionView struct {
	ClientID string `json:"client_id"`
	Name     string `json:"name"`
	URL      string `json:"url,omitempty"`
}

// resolveUser tries session cookie first, then Bearer token.
func (s *ConsoleService) resolveUser(ctx context.Context, sessionID, authHeader string) (*storage.User, error) {
	if sessionID != "" {
		user, err := s.store.GetValidSession(ctx, sessionID)
		if err == nil {
			return user, nil
		}
	}
	if authHeader != "" {
		return s.store.ValidateBearerToken(ctx, authHeader)
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

	clientIDs, err := s.store.GetActiveConnections(ctx, user.ID)
	if err != nil {
		return &ConnectionsResult{ErrorCode: http.StatusInternalServerError}
	}

	allClients := s.store.ListAllClients()
	type clientMeta struct{ name, url string }
	metaByID := make(map[string]clientMeta, len(allClients))
	for _, c := range allClients {
		metaByID[c.ClientID] = clientMeta{name: c.Name, url: c.URL}
	}

	views := make([]ConnectionView, 0, len(clientIDs))
	for _, id := range clientIDs {
		meta := metaByID[id]
		name := meta.name
		if name == "" {
			name = id
		}
		views = append(views, ConnectionView{ClientID: id, Name: name, URL: meta.url})
	}
	return &ConnectionsResult{Connections: views}
}
