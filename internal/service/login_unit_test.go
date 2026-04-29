package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type fakeLoginStore struct {
	getValidSessionFn         func(ctx context.Context, sessionID string) (*storage.User, error)
	auditLogFn                func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error
	recoverUserFn             func(ctx context.Context, userID string) error
	completeAuthRequestFn     func(ctx context.Context, authRequestID, userID string) error
	getUserByProviderIdentity func(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	createUserWithIdentityFn  func(ctx context.Context, input storage.CreateUserWithIdentityInput) (*storage.User, error)
	getUserByIDFn             func(ctx context.Context, userID string) (*storage.User, error)
	createSessionFn           func(ctx context.Context, userID string, ttl time.Duration) (string, error)
	getAuthRequestModelFn     func(ctx context.Context, id string) (*storage.AuthRequestModel, error)
}

func (f *fakeLoginStore) GetValidSession(ctx context.Context, sessionID string) (*storage.User, error) {
	return f.getValidSessionFn(ctx, sessionID)
}

func (f *fakeLoginStore) AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
	if f.auditLogFn == nil {
		return nil
	}
	return f.auditLogFn(ctx, userID, eventType, ipAddress, userAgent, metadata)
}

func (f *fakeLoginStore) RecoverUser(ctx context.Context, userID string) error {
	return f.recoverUserFn(ctx, userID)
}

func (f *fakeLoginStore) CompleteAuthRequest(ctx context.Context, authRequestID, userID string) error {
	return f.completeAuthRequestFn(ctx, authRequestID, userID)
}

func (f *fakeLoginStore) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error) {
	return f.getUserByProviderIdentity(ctx, provider, providerUserID)
}

func (f *fakeLoginStore) CreateUserWithIdentity(ctx context.Context, input storage.CreateUserWithIdentityInput) (*storage.User, error) {
	return f.createUserWithIdentityFn(ctx, input)
}

func (f *fakeLoginStore) GetUserByID(ctx context.Context, userID string) (*storage.User, error) {
	return f.getUserByIDFn(ctx, userID)
}

func (f *fakeLoginStore) CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	return f.createSessionFn(ctx, userID, ttl)
}

func TestLogin_HandleLogin_RecoversPendingDeletionSession(t *testing.T) {
	calledRecover := false
	calledComplete := false

	store := &fakeLoginStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "pending_deletion"}, nil
		},
		recoverUserFn: func(context.Context, string) error {
			calledRecover = true
			return nil
		},
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "client-a"}, nil
		},
		completeAuthRequestFn: func(context.Context, string, string) error {
			calledComplete = true
			return nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "s1"}}
	svc := NewLoginService(store, provider, 24*time.Hour)

	result := svc.HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")

	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want %v", result.Action, ActionAutoApprove)
	}
	if !calledRecover {
		t.Fatal("RecoverUser should be called for pending_deletion")
	}
	if !calledComplete {
		t.Fatal("CompleteAuthRequest should be called")
	}
}

func TestLogin_HandleCallback_EmailConflict(t *testing.T) {
	store := &fakeLoginStore{
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "client-a"}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return nil, storage.ErrNotFound
		},
		createUserWithIdentityFn: func(context.Context, storage.CreateUserWithIdentityInput) (*storage.User, error) {
			return nil, storage.ErrEmailConflict
		},
	}
	provider := &upstream.FakeProvider{
		ProviderName: "google",
		User: &upstream.UserInfo{
			Sub:           "sub-1",
			Email:         "dup@example.com",
			EmailVerified: true,
			Name:          "Dup",
		},
	}
	svc := NewLoginService(store, provider, 24*time.Hour)

	result := svc.HandleCallback(context.Background(), "code", "ar-1", "127.0.0.1", "ua")

	if result.Action != ActionError {
		t.Fatalf("action = %v, want %v", result.Action, ActionError)
	}
	if result.ErrorCode != 409 {
		t.Fatalf("errorCode = %d, want 409", result.ErrorCode)
	}
}

func TestLogin_HandleCallback_ExistingUser_AuditLogIncludesSessionAndClient(t *testing.T) {
	var gotEventType string
	var gotMetadata map[string]any
	store := &fakeLoginStore{
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "client-a"}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		createSessionFn: func(context.Context, string, time.Duration) (string, error) {
			return "sess-1", nil
		},
		completeAuthRequestFn: func(context.Context, string, string) error {
			return nil
		},
		auditLogFn: func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
			gotEventType = eventType
			gotMetadata = metadata
			return nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub-1"}}
	svc := NewLoginService(store, provider, 24*time.Hour)

	result := svc.HandleCallback(context.Background(), "code", "ar-1", "127.0.0.1", "ua")

	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want %v", result.Action, ActionAutoApprove)
	}
	if gotEventType != "auth.login" {
		t.Fatalf("eventType = %q, want auth.login", gotEventType)
	}
	if gotMetadata["channel"] != "browser" || gotMetadata["session_id"] != "sess-1" || gotMetadata["client_id"] != "client-a" {
		t.Fatalf("metadata = %#v", gotMetadata)
	}
}

func TestLogin_HandleCallback_SignupAuditLogIncludesChannel(t *testing.T) {
	type auditEntry struct {
		eventType string
		metadata  map[string]any
	}
	var gotEvents []auditEntry
	store := &fakeLoginStore{
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "client-a"}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return nil, storage.ErrNotFound
		},
		createUserWithIdentityFn: func(context.Context, storage.CreateUserWithIdentityInput) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		createSessionFn: func(context.Context, string, time.Duration) (string, error) {
			return "sess-1", nil
		},
		completeAuthRequestFn: func(context.Context, string, string) error {
			return nil
		},
		auditLogFn: func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
			gotEvents = append(gotEvents, auditEntry{eventType: eventType, metadata: metadata})
			return nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub-1"}}
	svc := NewLoginService(store, provider, 24*time.Hour)

	result := svc.HandleCallback(context.Background(), "code", "ar-1", "127.0.0.1", "ua")

	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want %v", result.Action, ActionAutoApprove)
	}
	var signupEvent *auditEntry
	for i := range gotEvents {
		if gotEvents[i].eventType == "auth.signup" {
			signupEvent = &gotEvents[i]
			break
		}
	}
	if signupEvent == nil {
		t.Fatalf("auth.signup event not found in %v", gotEvents)
	}
	if signupEvent.metadata["channel"] != "browser" {
		t.Fatalf("signup metadata = %#v", signupEvent.metadata)
	}
}

func TestMCPLogin_HandleCallback_AuditLogIncludesSessionAndClient(t *testing.T) {
	var gotEventType string
	var gotMetadata map[string]any
	store := &fakeLoginStore{
		getAuthRequestModelFn: func(context.Context, string) (*storage.AuthRequestModel, error) {
			return &storage.AuthRequestModel{ID: "ar-1", ClientID: "mcp-client", Resource: "http://localhost/mcp"}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		createSessionFn: func(context.Context, string, time.Duration) (string, error) {
			return "sess-1", nil
		},
		completeAuthRequestFn: func(context.Context, string, string) error {
			return nil
		},
		auditLogFn: func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
			gotEventType = eventType
			gotMetadata = metadata
			return nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub-1"}}
	svc := NewMCPLoginService(store, provider, 24*time.Hour)

	result := svc.HandleCallback(context.Background(), "code", "ar-1", "127.0.0.1", "ua")

	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want %v", result.Action, ActionAutoApprove)
	}
	if gotEventType != "auth.login" {
		t.Fatalf("eventType = %q, want auth.login", gotEventType)
	}
	if gotMetadata["channel"] != "mcp" || gotMetadata["session_id"] != "sess-1" || gotMetadata["client_id"] != "mcp-client" {
		t.Fatalf("metadata = %#v", gotMetadata)
	}
}

func TestLogin_HandleLogin_NoSession_Redirect(t *testing.T) {
	store := &fakeLoginStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return nil, errors.New("no session")
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "s1"}}
	svc := NewLoginService(store, provider, 24*time.Hour)

	result := svc.HandleLogin(context.Background(), "ar-1", "sess-1", "127.0.0.1", "ua")

	if result.Action != ActionRedirectToIdP {
		t.Fatalf("action = %v, want %v", result.Action, ActionRedirectToIdP)
	}
}

func (f *fakeLoginStore) GetAuthRequestModel(ctx context.Context, id string) (*storage.AuthRequestModel, error) {
	if f.getAuthRequestModelFn != nil {
		return f.getAuthRequestModelFn(ctx, id)
	}
	return nil, storage.ErrNotFound
}
