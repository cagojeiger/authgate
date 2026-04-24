package service

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/storage"
)

type fakeConsoleStore struct {
	getValidSessionFn          func(ctx context.Context, sessionID string) (*storage.User, error)
	validateBearerFn           func(ctx context.Context, authHeader string) (*storage.User, error)
	validateBearerWithClientFn func(ctx context.Context, authHeader string) (*storage.User, string, error)
	listAllClientsFn           func() []storage.ClientView
	getActiveConnFn            func(ctx context.Context, userID string) ([]storage.ConnectionTokenInfo, error)
	revokeConnectionFn         func(ctx context.Context, userID, clientID string) (int64, error)
	getActiveSessionsFn        func(ctx context.Context, userID string) ([]storage.SessionInfo, error)
	revokeSessionFn            func(ctx context.Context, userID, sessionID string) (int64, error)
	revokeOtherSessionsFn      func(ctx context.Context, userID, currentSessionID string) error
	getAuditLogFn              func(ctx context.Context, userID string, limit, offset int) (*storage.AuditLogPage, error)
	auditLogFn                 func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error
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
func (f *fakeConsoleStore) ValidateBearerTokenWithClientID(ctx context.Context, authHeader string) (*storage.User, string, error) {
	if f.validateBearerWithClientFn != nil {
		return f.validateBearerWithClientFn(ctx, authHeader)
	}
	user, err := f.ValidateBearerToken(ctx, authHeader)
	return user, "", err
}
func (f *fakeConsoleStore) ListAllClients() []storage.ClientView {
	return f.listAllClientsFn()
}
func (f *fakeConsoleStore) GetActiveConnections(ctx context.Context, userID string) ([]storage.ConnectionTokenInfo, error) {
	return f.getActiveConnFn(ctx, userID)
}
func (f *fakeConsoleStore) RevokeConnection(ctx context.Context, userID, clientID string) (int64, error) {
	return f.revokeConnectionFn(ctx, userID, clientID)
}
func (f *fakeConsoleStore) GetActiveSessions(ctx context.Context, userID string) ([]storage.SessionInfo, error) {
	return f.getActiveSessionsFn(ctx, userID)
}
func (f *fakeConsoleStore) RevokeSession(ctx context.Context, userID, sessionID string) (int64, error) {
	return f.revokeSessionFn(ctx, userID, sessionID)
}
func (f *fakeConsoleStore) RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) error {
	return f.revokeOtherSessionsFn(ctx, userID, currentSessionID)
}
func (f *fakeConsoleStore) GetAuditLog(ctx context.Context, userID string, limit, offset int) (*storage.AuditLogPage, error) {
	return f.getAuditLogFn(ctx, userID, limit, offset)
}
func (f *fakeConsoleStore) AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
	if f.auditLogFn == nil {
		return nil
	}
	return f.auditLogFn(ctx, userID, eventType, ipAddress, userAgent, metadata)
}

func activeUserStore(clients []storage.ClientView, connIDs []string) *fakeConsoleStore {
	connections := make([]storage.ConnectionTokenInfo, 0, len(connIDs))
	for _, id := range connIDs {
		connections = append(connections, storage.ConnectionTokenInfo{ClientID: id})
	}
	return &fakeConsoleStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		listAllClientsFn:   func() []storage.ClientView { return clients },
		getActiveConnFn:    func(context.Context, string) ([]storage.ConnectionTokenInfo, error) { return connections, nil },
		revokeConnectionFn: func(context.Context, string, string) (int64, error) { return 1, nil },
		getActiveSessionsFn: func(context.Context, string) ([]storage.SessionInfo, error) {
			return nil, nil
		},
		revokeSessionFn:       func(context.Context, string, string) (int64, error) { return 1, nil },
		revokeOtherSessionsFn: func(context.Context, string, string) error { return nil },
		getAuditLogFn: func(context.Context, string, int, int) (*storage.AuditLogPage, error) {
			return &storage.AuditLogPage{}, nil
		},
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
		listAllClientsFn:   func() []storage.ClientView { return nil },
		getActiveConnFn:    func(context.Context, string) ([]storage.ConnectionTokenInfo, error) { return nil, nil },
		revokeConnectionFn: func(context.Context, string, string) (int64, error) { return 1, nil },
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
		listAllClientsFn:   func() []storage.ClientView { return nil },
		getActiveConnFn:    func(context.Context, string) ([]storage.ConnectionTokenInfo, error) { return nil, nil },
		revokeConnectionFn: func(context.Context, string, string) (int64, error) { return 1, nil },
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
		listAllClientsFn:   func() []storage.ClientView { return nil },
		getActiveConnFn:    func(context.Context, string) ([]storage.ConnectionTokenInfo, error) { return nil, nil },
		revokeConnectionFn: func(context.Context, string, string) (int64, error) { return 1, nil },
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
		getActiveConnFn: func(context.Context, string) ([]storage.ConnectionTokenInfo, error) {
			return nil, errors.New("db error")
		},
		revokeConnectionFn: func(context.Context, string, string) (int64, error) { return 1, nil },
	}
	svc := NewConsoleService(store)
	r := svc.ListConnections(context.Background(), "sess-1", "")
	if r.ErrorCode != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", r.ErrorCode)
	}
}

func TestConsole_ListConnections_IncludesScopes(t *testing.T) {
	store := activeUserStore([]storage.ClientView{{ClientID: "app-a", Name: "App A"}}, nil)
	store.getActiveConnFn = func(context.Context, string) ([]storage.ConnectionTokenInfo, error) {
		return []storage.ConnectionTokenInfo{{
			ClientID: "app-a",
			Scopes:   []string{"openid", "profile"},
		}}, nil
	}
	svc := NewConsoleService(store)
	r := svc.ListConnections(context.Background(), "sess-1", "")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if !reflect.DeepEqual(r.Connections[0].Scopes, []string{"openid", "profile"}) {
		t.Fatalf("scopes = %#v, want [openid profile]", r.Connections[0].Scopes)
	}
}

func TestConsole_ListConnections_IncludesLastUsedWhenPresent(t *testing.T) {
	usedAt := time.Date(2026, 4, 24, 10, 11, 12, 0, time.FixedZone("KST", 9*60*60))
	store := activeUserStore([]storage.ClientView{{ClientID: "app-a", Name: "App A"}}, nil)
	store.getActiveConnFn = func(context.Context, string) ([]storage.ConnectionTokenInfo, error) {
		return []storage.ConnectionTokenInfo{{ClientID: "app-a", LastUsed: &usedAt}}, nil
	}
	svc := NewConsoleService(store)
	r := svc.ListConnections(context.Background(), "sess-1", "")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if r.Connections[0].LastUsed != "2026-04-24T01:11:12Z" {
		t.Fatalf("last_used = %q, want %q", r.Connections[0].LastUsed, "2026-04-24T01:11:12Z")
	}
}

func TestConsole_ListConnections_LastUsedEmptyWhenMissing(t *testing.T) {
	store := activeUserStore([]storage.ClientView{{ClientID: "app-a", Name: "App A"}}, nil)
	store.getActiveConnFn = func(context.Context, string) ([]storage.ConnectionTokenInfo, error) {
		return []storage.ConnectionTokenInfo{{ClientID: "app-a"}}, nil
	}
	svc := NewConsoleService(store)
	r := svc.ListConnections(context.Background(), "sess-1", "")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if r.Connections[0].LastUsed != "" {
		t.Fatalf("last_used = %q, want empty string", r.Connections[0].LastUsed)
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
		listAllClientsFn:   func() []storage.ClientView { return nil },
		getActiveConnFn:    func(context.Context, string) ([]storage.ConnectionTokenInfo, error) { return nil, nil },
		revokeConnectionFn: func(context.Context, string, string) (int64, error) { return 1, nil },
		getActiveSessionsFn: func(context.Context, string) ([]storage.SessionInfo, error) {
			return nil, nil
		},
		revokeSessionFn:       func(context.Context, string, string) (int64, error) { return 1, nil },
		revokeOtherSessionsFn: func(context.Context, string, string) error { return nil },
		getAuditLogFn: func(context.Context, string, int, int) (*storage.AuditLogPage, error) {
			return &storage.AuditLogPage{}, nil
		},
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
	store.getActiveConnFn = func(context.Context, string) ([]storage.ConnectionTokenInfo, error) {
		return []storage.ConnectionTokenInfo{{ClientID: "app-a"}}, nil
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
		listAllClientsFn:   func() []storage.ClientView { return nil },
		getActiveConnFn:    func(context.Context, string) ([]storage.ConnectionTokenInfo, error) { return nil, nil },
		revokeConnectionFn: func(context.Context, string, string) (int64, error) { return 1, nil },
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

// --- RevokeConnection ---

func TestConsole_RevokeConnection_NoSessionOrBearer_Unauthorized(t *testing.T) {
	svc := NewConsoleService(activeUserStore(nil, nil))
	r := svc.RevokeConnection(context.Background(), "", "", "app-a")
	if r.ErrorCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", r.ErrorCode)
	}
}

func TestConsole_RevokeConnection_ValidAuth_RevokesTokens(t *testing.T) {
	var gotUserID, gotClientID string
	store := activeUserStore(nil, nil)
	store.revokeConnectionFn = func(ctx context.Context, userID, clientID string) (int64, error) {
		gotUserID = userID
		gotClientID = clientID
		return 1, nil
	}
	svc := NewConsoleService(store)
	r := svc.RevokeConnection(context.Background(), "sess-1", "", "app-a")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if gotUserID != "u1" || gotClientID != "app-a" {
		t.Fatalf("revoke called with userID=%q clientID=%q", gotUserID, gotClientID)
	}
}

func TestConsole_RevokeConnection_ValidAuth_AuditLogsConnectionRevoked(t *testing.T) {
	var gotUserID, gotEventType string
	var gotMetadata map[string]any
	store := activeUserStore(nil, nil)
	store.auditLogFn = func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
		if userID != nil {
			gotUserID = *userID
		}
		gotEventType = eventType
		gotMetadata = metadata
		return nil
	}
	svc := NewConsoleService(store)

	r := svc.RevokeConnection(context.Background(), "sess-1", "", "app-a")

	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if gotUserID != "u1" || gotEventType != "auth.connection_revoked" {
		t.Fatalf("audit userID=%q eventType=%q", gotUserID, gotEventType)
	}
	if gotMetadata["client_id"] != "app-a" {
		t.Fatalf("metadata client_id=%v, want app-a", gotMetadata["client_id"])
	}
}

func TestConsole_RevokeConnection_OwnClient_BadRequest(t *testing.T) {
	store := bearerStore(&storage.User{ID: "u1", Status: "active"}, nil)
	store.validateBearerWithClientFn = func(context.Context, string) (*storage.User, string, error) {
		return &storage.User{ID: "u1", Status: "active"}, "app-a", nil
	}
	revokeCalled := false
	store.revokeConnectionFn = func(context.Context, string, string) (int64, error) {
		revokeCalled = true
		return 1, nil
	}
	svc := NewConsoleService(store)
	r := svc.RevokeConnection(context.Background(), "", "Bearer valid-token", "app-a")
	if r.ErrorCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", r.ErrorCode)
	}
	if revokeCalled {
		t.Fatal("revoke should not be called")
	}
}

func TestConsole_RevokeConnection_DBError_InternalServerError(t *testing.T) {
	store := activeUserStore(nil, nil)
	store.revokeConnectionFn = func(context.Context, string, string) (int64, error) {
		return 0, errors.New("db error")
	}
	svc := NewConsoleService(store)
	r := svc.RevokeConnection(context.Background(), "sess-1", "", "app-a")
	if r.ErrorCode != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", r.ErrorCode)
	}
}

func TestConsole_RevokeConnection_UnknownClient_NotFound_NoAudit(t *testing.T) {
	auditCalled := false
	store := activeUserStore(nil, nil)
	store.revokeConnectionFn = func(context.Context, string, string) (int64, error) {
		return 0, nil
	}
	store.auditLogFn = func(context.Context, *string, string, string, string, map[string]any) error {
		auditCalled = true
		return nil
	}
	svc := NewConsoleService(store)

	r := svc.RevokeConnection(context.Background(), "sess-1", "", "unknown-client")

	if r.ErrorCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", r.ErrorCode)
	}
	if auditCalled {
		t.Fatal("audit should not be called")
	}
}

// --- Sessions ---

func TestConsole_ListSessions_MarksCurrentSession(t *testing.T) {
	expiresAt := time.Date(2026, 4, 24, 12, 0, 0, 0, time.FixedZone("KST", 9*60*60))
	createdAt := time.Date(2026, 4, 24, 10, 0, 0, 0, time.FixedZone("KST", 9*60*60))
	store := activeUserStore(nil, nil)
	store.getActiveSessionsFn = func(context.Context, string) ([]storage.SessionInfo, error) {
		return []storage.SessionInfo{
			{ID: "sess-1", ExpiresAt: expiresAt, IPAddress: "127.0.0.1", UserAgent: "Browser", CreatedAt: &createdAt},
			{ID: "sess-2", ExpiresAt: expiresAt},
		}, nil
	}
	svc := NewConsoleService(store)
	r := svc.ListSessions(context.Background(), "sess-1", "")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if len(r.Sessions) != 2 {
		t.Fatalf("want 2 sessions, got %d", len(r.Sessions))
	}
	if !r.Sessions[0].IsCurrent || r.Sessions[1].IsCurrent {
		t.Fatalf("current flags = %#v", r.Sessions)
	}
	if r.Sessions[0].ExpiresAt != "2026-04-24T03:00:00Z" || r.Sessions[0].CreatedAt != "2026-04-24T01:00:00Z" {
		t.Fatalf("unexpected times: %+v", r.Sessions[0])
	}
}

func TestConsole_ListSessions_BearerAuth_NeverMarksCurrent(t *testing.T) {
	store := bearerStore(&storage.User{ID: "u1", Status: "active"}, nil)
	store.getActiveSessionsFn = func(context.Context, string) ([]storage.SessionInfo, error) {
		return []storage.SessionInfo{{ID: "sess-1", ExpiresAt: time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)}}, nil
	}
	svc := NewConsoleService(store)
	r := svc.ListSessions(context.Background(), "", "Bearer valid-token")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if len(r.Sessions) != 1 || r.Sessions[0].IsCurrent {
		t.Fatalf("unexpected sessions: %+v", r.Sessions)
	}
}

func TestConsole_RevokeSession_ValidAuth_RevokesAndAudits(t *testing.T) {
	var gotUserID, gotSessionID, gotEventType string
	var gotMetadata map[string]any
	store := activeUserStore(nil, nil)
	store.revokeSessionFn = func(ctx context.Context, userID, sessionID string) (int64, error) {
		gotUserID = userID
		gotSessionID = sessionID
		return 1, nil
	}
	store.auditLogFn = func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
		gotEventType = eventType
		gotMetadata = metadata
		return nil
	}
	svc := NewConsoleService(store)
	r := svc.RevokeSession(context.Background(), "sess-1", "", "sess-2")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if gotUserID != "u1" || gotSessionID != "sess-2" {
		t.Fatalf("revoke called with userID=%q sessionID=%q", gotUserID, gotSessionID)
	}
	if gotEventType != "auth.session_revoked" || gotMetadata["session_id"] != "sess-2" {
		t.Fatalf("audit event=%q metadata=%#v", gotEventType, gotMetadata)
	}
}

func TestConsole_RevokeSession_UnknownSession_NotFound_NoAudit(t *testing.T) {
	auditCalled := false
	store := activeUserStore(nil, nil)
	store.revokeSessionFn = func(context.Context, string, string) (int64, error) {
		return 0, nil
	}
	store.auditLogFn = func(context.Context, *string, string, string, string, map[string]any) error {
		auditCalled = true
		return nil
	}
	svc := NewConsoleService(store)

	r := svc.RevokeSession(context.Background(), "sess-1", "", "unknown-session")

	if r.ErrorCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", r.ErrorCode)
	}
	if auditCalled {
		t.Fatal("audit should not be called")
	}
}

func TestConsole_RevokeOtherSessions_RequiresCookieSession(t *testing.T) {
	store := bearerStore(&storage.User{ID: "u1", Status: "active"}, nil)
	called := false
	store.revokeOtherSessionsFn = func(context.Context, string, string) error {
		called = true
		return nil
	}
	svc := NewConsoleService(store)
	r := svc.RevokeOtherSessions(context.Background(), "", "Bearer valid-token")
	if r.ErrorCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", r.ErrorCode)
	}
	if called {
		t.Fatal("revoke other sessions should not be called for bearer-only auth")
	}
}

func TestConsole_RevokeOtherSessions_RevokesExceptCurrent(t *testing.T) {
	var gotUserID, gotCurrentSessionID string
	store := activeUserStore(nil, nil)
	store.revokeOtherSessionsFn = func(ctx context.Context, userID, currentSessionID string) error {
		gotUserID = userID
		gotCurrentSessionID = currentSessionID
		return nil
	}
	svc := NewConsoleService(store)
	r := svc.RevokeOtherSessions(context.Background(), "sess-1", "")
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if gotUserID != "u1" || gotCurrentSessionID != "sess-1" {
		t.Fatalf("revoke others called with userID=%q current=%q", gotUserID, gotCurrentSessionID)
	}
}

// --- Audit log ---

func TestConsole_GetAuditLog_DefaultsAndFormats(t *testing.T) {
	createdAt := time.Date(2026, 4, 24, 10, 11, 12, 0, time.FixedZone("KST", 9*60*60))
	var gotLimit, gotOffset int
	store := activeUserStore(nil, nil)
	store.getAuditLogFn = func(ctx context.Context, userID string, limit, offset int) (*storage.AuditLogPage, error) {
		gotLimit = limit
		gotOffset = offset
		return &storage.AuditLogPage{
			Events: []storage.AuditEventInfo{{
				ID:        7,
				EventType: "auth.login",
				IPAddress: "127.0.0.1",
				UserAgent: "Browser",
				Metadata:  map[string]any{"session_id": "sess-1"},
				CreatedAt: createdAt,
			}},
			Total: 42,
		}, nil
	}
	svc := NewConsoleService(store)
	r := svc.GetAuditLog(context.Background(), "sess-1", "", 0, 0)
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if gotLimit != 20 || gotOffset != 0 || r.Page != 1 || r.Limit != 20 || r.Total != 42 {
		t.Fatalf("pagination got limit=%d offset=%d result=%+v", gotLimit, gotOffset, r)
	}
	if len(r.Events) != 1 || r.Events[0].CreatedAt != "2026-04-24T01:11:12Z" {
		t.Fatalf("unexpected events: %+v", r.Events)
	}
}

func TestConsole_GetAuditLog_ClampsLimitAndOffsetsPage(t *testing.T) {
	var gotLimit, gotOffset int
	store := activeUserStore(nil, nil)
	store.getAuditLogFn = func(ctx context.Context, userID string, limit, offset int) (*storage.AuditLogPage, error) {
		gotLimit = limit
		gotOffset = offset
		return &storage.AuditLogPage{}, nil
	}
	svc := NewConsoleService(store)
	r := svc.GetAuditLog(context.Background(), "sess-1", "", 3, 500)
	if r.ErrorCode != 0 {
		t.Fatalf("want success, got %d", r.ErrorCode)
	}
	if gotLimit != 100 || gotOffset != 200 || r.Page != 3 || r.Limit != 100 {
		t.Fatalf("pagination got limit=%d offset=%d result=%+v", gotLimit, gotOffset, r)
	}
}
