package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/storage"
)

type fakeAccountStore struct {
	getValidSessionFn func(ctx context.Context, sessionID string) (*storage.User, error)
	requestDeletionFn func(ctx context.Context, userID string) error
	auditLogFn        func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
}

func (f *fakeAccountStore) GetValidSession(ctx context.Context, sessionID string) (*storage.User, error) {
	return f.getValidSessionFn(ctx, sessionID)
}

func (f *fakeAccountStore) RequestDeletion(ctx context.Context, userID string) error {
	return f.requestDeletionFn(ctx, userID)
}

func (f *fakeAccountStore) AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) {
	if f.auditLogFn == nil {
		return
	}
	f.auditLogFn(ctx, userID, eventType, ipAddress, userAgent, metadata)
}

func TestAccount_RequestDeletion_PendingDeletion_IsIdempotent(t *testing.T) {
	calledDelete := false
	store := &fakeAccountStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "pending_deletion"}, nil
		},
		requestDeletionFn: func(context.Context, string) error {
			calledDelete = true
			return nil
		},
	}
	svc := NewAccountService(store)

	result := svc.RequestDeletion(context.Background(), "sess-1", "127.0.0.1", "ua")

	if !result.Success {
		t.Fatal("pending_deletion should be idempotent success")
	}
	if !strings.Contains(result.Message, "Already pending deletion") {
		t.Fatalf("unexpected message: %q", result.Message)
	}
	if calledDelete {
		t.Fatal("RequestDeletion should not be called for pending_deletion")
	}
}

func TestAccount_RequestDeletion_ActiveUser_Success(t *testing.T) {
	calledDelete := false
	calledAudit := false
	store := &fakeAccountStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		requestDeletionFn: func(context.Context, string) error {
			calledDelete = true
			return nil
		},
		auditLogFn: func(context.Context, *string, string, string, string, map[string]any) {
			calledAudit = true
		},
	}
	svc := NewAccountService(store)

	result := svc.RequestDeletion(context.Background(), "sess-1", "127.0.0.1", "ua")

	if !result.Success {
		t.Fatalf("expected success, got message=%q", result.Message)
	}
	if !calledDelete {
		t.Fatal("RequestDeletion should be called")
	}
	if !calledAudit {
		t.Fatal("AuditLog should be called")
	}
}

func TestAccount_RequestDeletion_InvalidSession(t *testing.T) {
	store := &fakeAccountStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return nil, errors.New("invalid")
		},
		requestDeletionFn: func(context.Context, string) error {
			return nil
		},
	}
	svc := NewAccountService(store)

	result := svc.RequestDeletion(context.Background(), "sess-1", "127.0.0.1", "ua")

	if result.Success {
		t.Fatal("invalid session should fail")
	}
	if result.ErrorCode != 401 {
		t.Fatalf("errorCode = %d, want 401", result.ErrorCode)
	}
}

