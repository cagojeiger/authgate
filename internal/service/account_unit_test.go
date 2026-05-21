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
	requestDeletionFn func(ctx context.Context, userID string) (string, error)
	auditLogFn        func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
}

func (f *fakeAccountStore) GetValidSession(ctx context.Context, sessionID string) (*storage.User, error) {
	return f.getValidSessionFn(ctx, sessionID)
}

func (f *fakeAccountStore) RequestDeletion(ctx context.Context, userID string) (string, error) {
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
		requestDeletionFn: func(context.Context, string) (string, error) {
			calledDelete = true
			return "", nil
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
		requestDeletionFn: func(context.Context, string) (string, error) {
			calledDelete = true
			return "", nil
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

// #183: when storage returns ErrUserAccountClosed (because the user was
// disabled between session validation and the conditional UPDATE), the
// service must (a) return 403 account_inactive and (b) audit the *live*
// status from storage, not the stale session-snapshot status. The audit
// metadata must also carry phase=account_deletion so operators can
// distinguish UPDATE-time rejections from session-time rejections.
func TestAccount_RequestDeletion_StorageRejectsClosedAccount(t *testing.T) {
	var auditMeta map[string]any
	var auditEventType string
	store := &fakeAccountStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			// session-time snapshot is still active (the race window)
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		requestDeletionFn: func(context.Context, string) (string, error) {
			// storage saw status flip to disabled inside its TX
			return "disabled", storage.ErrUserAccountClosed
		},
		auditLogFn: func(_ context.Context, _ *string, eventType, _, _ string, metadata map[string]any) {
			auditEventType = eventType
			auditMeta = metadata
		},
	}
	svc := NewAccountService(store)

	result := svc.RequestDeletion(context.Background(), "sess-1", "127.0.0.1", "ua")

	if result.Success {
		t.Fatal("storage rejection must produce failure result")
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
	if result.Message != "account_inactive" {
		t.Errorf("message = %q, want account_inactive", result.Message)
	}
	if auditEventType != "auth.inactive_user" {
		t.Errorf("audit event_type = %q, want auth.inactive_user", auditEventType)
	}
	if auditMeta["status"] != "disabled" {
		t.Errorf("audit status = %v, want %q (live status from storage, not session snapshot)", auditMeta["status"], "disabled")
	}
	if auditMeta["phase"] != "account_deletion" {
		t.Errorf("audit phase = %v, want account_deletion", auditMeta["phase"])
	}
	if auditMeta["channel"] != "browser" {
		t.Errorf("audit channel = %v, want browser", auditMeta["channel"])
	}
}

func TestAccount_RequestDeletion_InvalidSession(t *testing.T) {
	store := &fakeAccountStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return nil, errors.New("invalid")
		},
		requestDeletionFn: func(context.Context, string) (string, error) {
			return "", nil
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
