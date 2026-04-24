package service

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/kangheeyong/authgate/internal/storage"
)

type fakeConsoleStore struct {
	getValidSessionFn   func(ctx context.Context, sessionID string) (*storage.User, error)
	validateBearerFn    func(ctx context.Context, authHeader string) (*storage.User, error)
	listAllClientsFn    func() []storage.ClientView
	getActiveConnFn     func(ctx context.Context, userID string) ([]string, error)
}

func (f *fakeConsoleStore) GetValidSession(ctx context.Context, sessionID string) (*storage.User, error) {
	return f.getValidSessionFn(ctx, sessionID)
}
func (f *fakeConsoleStore) ValidateBearerToken(ctx context.Context, authHeader string) (*storage.User, error) {
	if f.validateBearerFn != nil {
		return f.validateBearerFn(ctx, authHeader)
	}
	return nil, errors.New("bearer not configured")
}
func (f *fakeConsoleStore) ListAllClients() []storage.ClientView {
	return f.listAllClientsFn()
}
func (f *fakeConsoleStore) GetActiveConnections(ctx context.Context, userID string) ([]string, error) {
	return f.getActiveConnFn(ctx, userID)
}

func activeUserStore(clients []storage.ClientView, connIDs []string) *fakeConsoleStore {
	return &fakeConsoleStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		listAllClientsFn: func() []storage.ClientView { return clients },
		getActiveConnFn:  func(context.Context, string) ([]string, error) { return connIDs, nil },
	}
}

// --- ListClients ---

func TestConsole_ListClients_NoSession_Unauthorized(t *testing.T) {
	svc := NewConsoleService(activeUserStore(nil, nil))
	r := svc.ListClients(context.Background(), "", "")
	if r.ErrorCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", r.ErrorCode)
	}
}

func TestConsole_ListClients_InvalidSession_Unauthorized(t *testing.T) {
	store := &fakeConsoleStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return nil, errors.New("not found")
		},
		listAllClientsFn: func() []storage.ClientView { return nil },
		getActiveConnFn:  func(context.Context, string) ([]string, error) { return nil, nil },
	}
	svc := NewConsoleService(store)
	r := svc.ListClients(context.Background(), "sess-x", "")
	if r.ErrorCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", r.ErrorCode)
	}
}

func TestConsole_ListClients_DisabledUser_Forbidden(t *testing.T) {
	store := &fakeConsoleStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "disabled"}, nil
		},
		listAllClientsFn: func() []storage.ClientView { return nil },
		getActiveConnFn:  func(context.Context, string) ([]string, error) { return nil, nil },
	}
	svc := NewConsoleService(store)
	r := svc.ListClients(context.Background(), "sess-1", "")
	if r.ErrorCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", r.ErrorCode)
	}
}

func TestConsole_ListClients_PendingDeletion_Forbidden(t *testing.T) {
	store := &fakeConsoleStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "pending_deletion"}, nil
		},
		listAllClientsFn: func() []storage.ClientView { return nil },
		getActiveConnFn:  func(context.Context, string) ([]string, error) { return nil, nil },
	}
	svc := NewConsoleService(store)
	r := svc.ListClients(context.Background(), "sess-1", "")
	if r.ErrorCode != http.StatusForbidden {
		t.Fatalf("pending_deletion: want 403, got %d", r.ErrorCode)
	}
}

func TestConsole_ListClients_ActiveUser_ReturnsClients(t *testing.T) {
	clients := []storage.ClientView{
		{ClientID: "app-a", Name: "App A"},
		{ClientID: "app-b", Name: "App B"},
	}
	svc := NewConsoleService(activeUserStore(clients, nil))
	r := svc.ListClients(context.Background(), "sess-1", "")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got error %d", r.ErrorCode)
	}
	if len(r.Clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(r.Clients))
	}
}

func TestConsole_ListClients_NilClients_ReturnsEmptySlice(t *testing.T) {
	svc := NewConsoleService(activeUserStore(nil, nil))
	r := svc.ListClients(context.Background(), "sess-1", "")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if r.Clients == nil {
		t.Fatal("want empty slice, got nil")
	}
}

// --- ListConnections ---

func TestConsole_ListConnections_NoSession_Unauthorized(t *testing.T) {
	svc := NewConsoleService(activeUserStore(nil, nil))
	r := svc.ListConnections(context.Background(), "", "")
	if r.ErrorCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", r.ErrorCode)
	}
}

func TestConsole_ListConnections_ActiveUser_EnrichesName(t *testing.T) {
	clients := []storage.ClientView{
		{ClientID: "app-a", Name: "App A"},
	}
	svc := NewConsoleService(activeUserStore(clients, []string{"app-a"}))
	r := svc.ListConnections(context.Background(), "sess-1", "")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if len(r.Connections) != 1 {
		t.Fatalf("want 1 connection, got %d", len(r.Connections))
	}
	if r.Connections[0].Name != "App A" {
		t.Fatalf("want name='App A', got %q", r.Connections[0].Name)
	}
}

func TestConsole_ListConnections_UnknownClient_FallsBackToClientID(t *testing.T) {
	svc := NewConsoleService(activeUserStore(nil, []string{"ghost-client"}))
	r := svc.ListConnections(context.Background(), "sess-1", "")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if len(r.Connections) != 1 {
		t.Fatalf("want 1 connection, got %d", len(r.Connections))
	}
	if r.Connections[0].Name != "ghost-client" {
		t.Fatalf("want fallback name='ghost-client', got %q", r.Connections[0].Name)
	}
}

func TestConsole_ListConnections_DBError_InternalServerError(t *testing.T) {
	store := &fakeConsoleStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		listAllClientsFn: func() []storage.ClientView { return nil },
		getActiveConnFn: func(context.Context, string) ([]string, error) {
			return nil, errors.New("db error")
		},
	}
	svc := NewConsoleService(store)
	r := svc.ListConnections(context.Background(), "sess-1", "")
	if r.ErrorCode != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", r.ErrorCode)
	}
}

// --- Bearer auth ---

func bearerStore(user *storage.User, bearerErr error) *fakeConsoleStore {
	return &fakeConsoleStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return nil, errors.New("no session")
		},
		validateBearerFn: func(context.Context, string) (*storage.User, error) {
			return user, bearerErr
		},
		listAllClientsFn: func() []storage.ClientView { return nil },
		getActiveConnFn:  func(context.Context, string) ([]string, error) { return nil, nil },
	}
}

func TestConsole_ListClients_BearerValid_ReturnsClients(t *testing.T) {
	store := bearerStore(&storage.User{ID: "u1", Status: "active"}, nil)
	store.listAllClientsFn = func() []storage.ClientView {
		return []storage.ClientView{{ClientID: "app-a", Name: "App A"}}
	}
	svc := NewConsoleService(store)
	r := svc.ListClients(context.Background(), "", "Bearer valid-token")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if len(r.Clients) != 1 {
		t.Fatalf("want 1 client, got %d", len(r.Clients))
	}
}

func TestConsole_ListClients_BearerInvalid_Unauthorized(t *testing.T) {
	svc := NewConsoleService(bearerStore(nil, errors.New("invalid token")))
	r := svc.ListClients(context.Background(), "", "Bearer bad-token")
	if r.ErrorCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", r.ErrorCode)
	}
}

func TestConsole_ListConnections_BearerValid_ReturnsConnections(t *testing.T) {
	store := bearerStore(&storage.User{ID: "u1", Status: "active"}, nil)
	store.getActiveConnFn = func(context.Context, string) ([]string, error) {
		return []string{"app-a"}, nil
	}
	store.listAllClientsFn = func() []storage.ClientView {
		return []storage.ClientView{{ClientID: "app-a", Name: "App A"}}
	}
	svc := NewConsoleService(store)
	r := svc.ListConnections(context.Background(), "", "Bearer valid-token")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if len(r.Connections) != 1 || r.Connections[0].Name != "App A" {
		t.Fatalf("unexpected connections: %+v", r.Connections)
	}
}

func TestConsole_ListClients_SessionWinsOverBearer(t *testing.T) {
	// session valid → bearer should never be called
	bearerCalled := false
	store := &fakeConsoleStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		validateBearerFn: func(context.Context, string) (*storage.User, error) {
			bearerCalled = true
			return nil, errors.New("should not be called")
		},
		listAllClientsFn: func() []storage.ClientView { return nil },
		getActiveConnFn:  func(context.Context, string) ([]string, error) { return nil, nil },
	}
	svc := NewConsoleService(store)
	r := svc.ListClients(context.Background(), "sess-1", "Bearer token")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if bearerCalled {
		t.Fatal("bearer should not be called when session is valid")
	}
}
