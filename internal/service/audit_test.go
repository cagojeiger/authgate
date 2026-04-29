//go:build integration

package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/storage"
)

type auditEventRow struct {
	EventType string
	Metadata  map[string]any
}

func fetchAuditEvents(t *testing.T, db *sql.DB, userID, eventType string) []auditEventRow {
	t.Helper()

	rows, err := db.QueryContext(context.Background(),
		`SELECT event_type, metadata
		 FROM audit_log
		 WHERE user_id = $1 AND event_type = $2
		 ORDER BY created_at ASC`,
		userID, eventType,
	)
	if err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	defer rows.Close()

	var events []auditEventRow
	for rows.Next() {
		var event auditEventRow
		var raw []byte
		if err := rows.Scan(&event.EventType, &raw); err != nil {
			t.Fatalf("scan audit event: %v", err)
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &event.Metadata); err != nil {
				t.Fatalf("decode audit metadata: %v", err)
			}
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit events: %v", err)
	}
	return events
}

func requireSingleAuditEvent(t *testing.T, db *sql.DB, userID, eventType string) auditEventRow {
	t.Helper()
	events := fetchAuditEvents(t, db, userID, eventType)
	if len(events) != 1 {
		t.Fatalf("audit %s count = %d, want 1", eventType, len(events))
	}
	return events[0]
}

func TestAudit001_BrowserSignup(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	arID, _ := store.CreateTestAuthRequest(ctx, "audit-signup")
	result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test-agent")
	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want AutoApprove", result.Action)
	}

	user, err := store.GetUserByProviderIdentity(ctx, "google", "google-sub-123")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	requireSingleAuditEvent(t, store.DB(), user.ID, "auth.signup")
}

func TestAudit002_LoginChannels(t *testing.T) {
	t.Run("browser", func(t *testing.T) {
		svc, store := setupBrowserExtTest(t)
		ctx := context.Background()

		user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-browser@test.com", EmailVerified: true, Name: "Browser", AvatarURL: "", Provider: "google", ProviderUserID: "browser-ext-sub", ProviderEmail: "audit-browser@test.com"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		arID, _ := store.CreateTestAuthRequest(ctx, "audit-browser")

		result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "browser-agent")
		if result.Action != ActionAutoApprove {
			t.Fatalf("action = %v, want AutoApprove", result.Action)
		}

		event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.login")
		if event.Metadata["channel"] != "browser" {
			t.Fatalf("channel = %v, want browser", event.Metadata["channel"])
		}
	})

	t.Run("device", func(t *testing.T) {
		svc, store, clk := setupDeviceExtTest(t, "audit-device-sub")
		ctx := context.Background()

		user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-device@test.com", EmailVerified: true, Name: "Device", AvatarURL: "", Provider: "google", ProviderUserID: "audit-device-sub", ProviderEmail: "audit-device@test.com"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		insertDeviceCode(t, store, "AUDT-DEV", clk)

		result := svc.HandleDeviceCallback(ctx, "fake-code", "AUDT-DEV", "127.0.0.1", "device-agent")
		if result.Action != DeviceRedirectBack {
			t.Fatalf("action = %v, want DeviceRedirectBack", result.Action)
		}

		event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.login")
		if event.Metadata["channel"] != "device" {
			t.Fatalf("channel = %v, want device", event.Metadata["channel"])
		}
	})

	t.Run("mcp", func(t *testing.T) {
		svc, store := setupMCPExtTest(t, "audit-mcp-sub")
		ctx := context.Background()

		user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-mcp@test.com", EmailVerified: true, Name: "MCP", AvatarURL: "", Provider: "google", ProviderUserID: "audit-mcp-sub", ProviderEmail: "audit-mcp@test.com"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		arID, _ := store.CreateTestAuthRequestWithResource(ctx, "audit-mcp", "http://localhost/mcp")

		result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-agent")
		if result.Action != ActionAutoApprove {
			t.Fatalf("action = %v, want AutoApprove", result.Action)
		}

		event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.login")
		if event.Metadata["channel"] != "mcp" {
			t.Fatalf("channel = %v, want mcp", event.Metadata["channel"])
		}
	})
}

func TestAudit004_DeviceApproved(t *testing.T) {
	svc, store, clk := setupDeviceService(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-approve@test.com", EmailVerified: true, Name: "Approve", AvatarURL: "", Provider: "google", ProviderUserID: "device-sub-123", ProviderEmail: "audit-approve@test.com"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	insertDeviceCode(t, store, "AUDT-APRV", clk)

	result := svc.HandleDeviceApprove(ctx, "AUDT-APRV", "approve", sessionID, "127.0.0.1", "approve-agent")
	if !result.Success {
		t.Fatalf("approve failed: %s", result.Message)
	}

	requireSingleAuditEvent(t, store.DB(), user.ID, "auth.device_approved")
}

func TestAudit005_DeviceDenied(t *testing.T) {
	svc, store, clk := setupDeviceService(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-deny@test.com", EmailVerified: true, Name: "Deny", AvatarURL: "", Provider: "google", ProviderUserID: "device-sub-123", ProviderEmail: "audit-deny@test.com"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	insertDeviceCode(t, store, "AUDT-DENY", clk)

	result := svc.HandleDeviceApprove(ctx, "AUDT-DENY", "deny", sessionID, "127.0.0.1", "deny-agent")
	if result.Success {
		t.Fatalf("deny should fail")
	}

	requireSingleAuditEvent(t, store.DB(), user.ID, "auth.device_denied")
}

func TestAudit006_DeletionRequested(t *testing.T) {
	svc, store := setupAccountExtTest(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-delete@test.com", EmailVerified: true, Name: "Delete", AvatarURL: "", Provider: "google", ProviderUserID: "audit-delete-sub", ProviderEmail: "audit-delete@test.com"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, err := store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	result := svc.RequestDeletion(ctx, sessionID, "127.0.0.1", "delete-agent")
	if !result.Success {
		t.Fatalf("request deletion failed: %s", result.Message)
	}

	requireSingleAuditEvent(t, store.DB(), user.ID, "auth.deletion_requested")
}

func TestAudit007_DeletionCancelled(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-recover@test.com", EmailVerified: true, Name: "Recover", AvatarURL: "", Provider: "google", ProviderUserID: "google-sub-123", ProviderEmail: "audit-recover@test.com"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := store.SetUserStatus(ctx, user.ID, "pending_deletion"); err != nil {
		t.Fatalf("set pending deletion: %v", err)
	}
	arID, _ := store.CreateTestAuthRequest(ctx, "audit-recover")

	result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "recover-agent")
	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want AutoApprove", result.Action)
	}

	requireSingleAuditEvent(t, store.DB(), user.ID, "auth.deletion_cancelled")
}

func TestAudit009_InactiveUser(t *testing.T) {
	tests := []struct {
		name   string
		status string
	}{
		{name: "disabled", status: "disabled"},
		{name: "deleted", status: "deleted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, store := setupLoginService(t)
			ctx := context.Background()

			user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-inactive-" + tt.name + "@test.com", EmailVerified: true, Name: "Inactive", AvatarURL: "", Provider: "google", ProviderUserID: "google-sub-123", ProviderEmail: "audit-inactive@test.com"})
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			if err := store.SetUserStatus(ctx, user.ID, tt.status); err != nil {
				t.Fatalf("set user status: %v", err)
			}
			arID, err := store.CreateTestAuthRequest(ctx, "audit-inactive-"+tt.name)
			if err != nil {
				t.Fatalf("create auth request: %v", err)
			}

			result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "inactive-agent")
			if result.Action != ActionError {
				t.Fatalf("action = %v, want Error", result.Action)
			}

			event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.inactive_user")
			if event.Metadata["status"] != tt.status {
				t.Fatalf("status = %v, want %s", event.Metadata["status"], tt.status)
			}
		})
	}
}

func TestAuditSecurity003_DeviceInactiveUser(t *testing.T) {
	svc, store, _ := setupDeviceExtTest(t, "audit-device-inactive-sub")
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-device-inactive@test.com", EmailVerified: true, Name: "Inactive Device", AvatarURL: "", Provider: "google", ProviderUserID: "audit-device-inactive-sub", ProviderEmail: "audit-device-inactive@test.com"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := store.SetUserStatus(ctx, user.ID, "disabled"); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	result := svc.HandleDeviceCallback(ctx, "fake-code", "AUDT-INAC", "127.0.0.1", "device-inactive-agent")
	if result.Action != DeviceError {
		t.Fatalf("action = %v, want DeviceError", result.Action)
	}

	event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.inactive_user")
	if event.Metadata["status"] != "disabled" {
		t.Fatalf("status = %v, want disabled", event.Metadata["status"])
	}
}

func TestAuditSecurity_DevicePendingDeletionInactiveUser(t *testing.T) {
	svc, store, _ := setupDeviceExtTest(t, "audit-device-pending-sub")
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-device-pending@test.com", EmailVerified: true, Name: "Pending Device", AvatarURL: "", Provider: "google", ProviderUserID: "audit-device-pending-sub", ProviderEmail: "audit-device-pending@test.com"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := store.SetUserStatus(ctx, user.ID, "pending_deletion"); err != nil {
		t.Fatalf("set pending_deletion: %v", err)
	}

	result := svc.HandleDeviceCallback(ctx, "fake-code", "AUDT-PEND", "127.0.0.1", "device-pending-agent")
	if result.Action != DeviceError {
		t.Fatalf("action = %v, want DeviceError", result.Action)
	}

	event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.inactive_user")
	if event.Metadata["status"] != "pending_deletion" {
		t.Fatalf("status = %v, want pending_deletion", event.Metadata["status"])
	}
	if event.Metadata["channel"] != "device" {
		t.Fatalf("channel = %v, want device", event.Metadata["channel"])
	}
}

func TestAuditSecurity_MCPInactiveUser_Metadata(t *testing.T) {
	tests := []struct {
		name   string
		status string
	}{
		{name: "pending_deletion", status: "pending_deletion"},
		{name: "disabled", status: "disabled"},
		{name: "deleted", status: "deleted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, store := setupMCPExtTest(t, "audit-mcp-"+tt.name+"-sub")
			ctx := context.Background()

			user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-mcp-" + tt.name + "@test.com", EmailVerified: true, Name: "MCP Inactive", AvatarURL: "", Provider: "google", ProviderUserID: "audit-mcp-" + tt.name + "-sub", ProviderEmail: "audit-mcp-" + tt.name + "@test.com"})
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			if err := store.SetUserStatus(ctx, user.ID, tt.status); err != nil {
				t.Fatalf("set status %s: %v", tt.status, err)
			}
			arID, _ := store.CreateTestAuthRequestWithResource(ctx, "audit-mcp-"+tt.name, "http://localhost/mcp")

			result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-agent")
			if result.Action != ActionError {
				t.Fatalf("action = %v, want ActionError", result.Action)
			}

			event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.inactive_user")
			if event.Metadata["status"] != tt.status {
				t.Fatalf("status = %v, want %s", event.Metadata["status"], tt.status)
			}
			if event.Metadata["channel"] != "mcp" {
				t.Fatalf("channel = %v, want mcp", event.Metadata["channel"])
			}

			loginEvents := fetchAuditEvents(t, store.DB(), user.ID, "auth.login")
			if len(loginEvents) != 0 {
				t.Fatalf("auth.login count = %d, want 0 for inactive MCP callback", len(loginEvents))
			}
		})
	}
}

var _ = storage.ErrNotFound
