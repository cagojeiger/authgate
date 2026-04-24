package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type fakeDeviceStore struct {
	getDeviceCodeByUserCodeFn func(ctx context.Context, userCode string) (*storage.DeviceCodeModel, error)
	getValidSessionFn         func(ctx context.Context, sessionID string) (*storage.User, error)
	auditLogFn                func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error
	getUserByProviderIdentity func(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	createSessionFn           func(ctx context.Context, userID string, ttl time.Duration) (string, error)
	denyDeviceCodeFn          func(ctx context.Context, userCode string) error
	approveDeviceCodeFn       func(ctx context.Context, userCode, subject string) error
}

func (f *fakeDeviceStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*storage.DeviceCodeModel, error) {
	return f.getDeviceCodeByUserCodeFn(ctx, userCode)
}

func (f *fakeDeviceStore) GetValidSession(ctx context.Context, sessionID string) (*storage.User, error) {
	return f.getValidSessionFn(ctx, sessionID)
}

func (f *fakeDeviceStore) AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
	if f.auditLogFn == nil {
		return nil
	}
	return f.auditLogFn(ctx, userID, eventType, ipAddress, userAgent, metadata)
}

func (f *fakeDeviceStore) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error) {
	return f.getUserByProviderIdentity(ctx, provider, providerUserID)
}

func (f *fakeDeviceStore) CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	return f.createSessionFn(ctx, userID, ttl)
}

func (f *fakeDeviceStore) DenyDeviceCode(ctx context.Context, userCode string) error {
	return f.denyDeviceCodeFn(ctx, userCode)
}

func (f *fakeDeviceStore) ApproveDeviceCode(ctx context.Context, userCode, subject string) error {
	return f.approveDeviceCodeFn(ctx, userCode, subject)
}

func TestDevice_HandleDevicePage_NoSession_Redirects(t *testing.T) {
	clk := &clock.FixedClock{T: time.Date(2026, 4, 3, 0, 0, 0, 0, time.UTC)}
	store := &fakeDeviceStore{
		getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
			return &storage.DeviceCodeModel{
				UserCode:  "UCODE",
				State:     "pending",
				ExpiresAt: clk.Now().Add(5 * time.Minute),
			}, nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub"}}
	svc := NewDeviceService(store, provider, "http://localhost", 24*time.Hour, clk)

	result := svc.HandleDevicePage(context.Background(), "UCODE", "")

	if result.Action != DeviceRedirectIdP {
		t.Fatalf("action = %v, want %v", result.Action, DeviceRedirectIdP)
	}
}

func TestDevice_HandleDeviceApprove_Deny(t *testing.T) {
	denyCalled := false
	store := &fakeDeviceStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		denyDeviceCodeFn: func(context.Context, string) error {
			denyCalled = true
			return nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub"}}
	svc := NewDeviceService(store, provider, "http://localhost", 24*time.Hour, clock.RealClock{})

	result := svc.HandleDeviceApprove(context.Background(), "UCODE", "deny", "sess", "127.0.0.1", "ua")

	if result.Success {
		t.Fatal("deny action should return success=false")
	}
	if !denyCalled {
		t.Fatal("DenyDeviceCode should be called")
	}
}

func TestDevice_HandleDeviceApprove_ApproveError(t *testing.T) {
	store := &fakeDeviceStore{
		getValidSessionFn: func(context.Context, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		approveDeviceCodeFn: func(context.Context, string, string) error {
			return errors.New("expired")
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub"}}
	svc := NewDeviceService(store, provider, "http://localhost", 24*time.Hour, clock.RealClock{})

	result := svc.HandleDeviceApprove(context.Background(), "UCODE", "approve", "sess", "127.0.0.1", "ua")

	if result.Success {
		t.Fatal("approve with error should fail")
	}
	if result.ErrorCode != 400 {
		t.Fatalf("errorCode = %d, want 400", result.ErrorCode)
	}
}

func TestDevice_HandleDeviceCallback_AuditLogIncludesSessionAndClient(t *testing.T) {
	var gotEventType string
	var gotMetadata map[string]any
	clk := &clock.FixedClock{T: time.Date(2026, 4, 3, 0, 0, 0, 0, time.UTC)}
	store := &fakeDeviceStore{
		getDeviceCodeByUserCodeFn: func(context.Context, string) (*storage.DeviceCodeModel, error) {
			return &storage.DeviceCodeModel{
				UserCode:  "UCODE",
				ClientID:  "device-client",
				State:     "pending",
				ExpiresAt: clk.Now().Add(5 * time.Minute),
			}, nil
		},
		getUserByProviderIdentity: func(context.Context, string, string) (*storage.User, error) {
			return &storage.User{ID: "u1", Status: "active"}, nil
		},
		createSessionFn: func(context.Context, string, time.Duration) (string, error) {
			return "sess-1", nil
		},
		auditLogFn: func(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error {
			gotEventType = eventType
			gotMetadata = metadata
			return nil
		},
	}
	provider := &upstream.FakeProvider{ProviderName: "google", User: &upstream.UserInfo{Sub: "sub"}}
	svc := NewDeviceService(store, provider, "http://localhost", 24*time.Hour, clk)

	result := svc.HandleDeviceCallback(context.Background(), "code", "UCODE", "127.0.0.1", "ua")

	if result.Action != DeviceRedirectBack {
		t.Fatalf("action = %v, want %v", result.Action, DeviceRedirectBack)
	}
	if gotEventType != "auth.login" {
		t.Fatalf("eventType = %q, want auth.login", gotEventType)
	}
	if gotMetadata["channel"] != "device" || gotMetadata["session_id"] != "sess-1" || gotMetadata["client_id"] != "device-client" {
		t.Fatalf("metadata = %#v", gotMetadata)
	}
}
