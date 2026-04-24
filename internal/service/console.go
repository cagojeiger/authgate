package service

import (
	"context"
	"net/http"

	"github.com/kangheeyong/authgate/internal/storage"
)

type ConsoleService struct {
	store ConsoleStore
}

type ConsoleStore interface {
	GetValidSession(ctx context.Context, sessionID string) (*storage.User, error)
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
}

func (s *ConsoleService) ListClients(ctx context.Context, sessionID string) *ClientsResult {
	if sessionID == "" {
		return &ClientsResult{ErrorCode: http.StatusUnauthorized}
	}
	user, err := s.store.GetValidSession(ctx, sessionID)
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

func (s *ConsoleService) ListConnections(ctx context.Context, sessionID string) *ConnectionsResult {
	if sessionID == "" {
		return &ConnectionsResult{ErrorCode: http.StatusUnauthorized}
	}
	user, err := s.store.GetValidSession(ctx, sessionID)
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

	// Enrich with client names from the in-memory registry.
	// Fall back to client_id as name when the registry entry no longer exists
	// (e.g. deleted YAML client with a lingering refresh token).
	allClients := s.store.ListAllClients()
	nameByID := make(map[string]string, len(allClients))
	for _, c := range allClients {
		nameByID[c.ClientID] = c.Name
	}

	views := make([]ConnectionView, 0, len(clientIDs))
	for _, id := range clientIDs {
		name := nameByID[id]
		if name == "" {
			name = id
		}
		views = append(views, ConnectionView{ClientID: id, Name: name})
	}
	return &ConnectionsResult{Connections: views}
}
