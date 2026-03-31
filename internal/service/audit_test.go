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

		user, err := store.CreateUserWithIdentity(ctx, "audit-browser@test.com", true, "Browser", "", "google", "browser-ext-sub", "audit-browser@test.com")
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
		svc, store, _ := setupDeviceExtTest(t, "audit-device-sub")
		ctx := context.Background()

		user, err := store.CreateUserWithIdentity(ctx, "audit-device@test.com", true, "Device", "", "google", "audit-device-sub", "audit-device@test.com")
		if err != nil {
			t.Fatalf("create user: %v", err)
		}

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

		user, err := store.CreateUserWithIdentity(ctx, "audit-mcp@test.com", true, "MCP", "", "google", "audit-mcp-sub", "audit-mcp@test.com")
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		arID, _ := store.CreateTestAuthRequest(ctx, "audit-mcp")

		result := svc.HandleMCPCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-agent")
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

	user, err := store.CreateUserWithIdentity(ctx, "audit-approve@test.com", true, "Approve", "", "google", "device-sub-123", "audit-approve@test.com")
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

	user, err := store.CreateUserWithIdentity(ctx, "audit-deny@test.com", true, "Deny", "", "google", "device-sub-123", "audit-deny@test.com")
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

	user, err := store.CreateUserWithIdentity(ctx, "audit-delete@test.com", true, "Delete", "", "google", "audit-delete-sub", "audit-delete@test.com")
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

	user, err := store.CreateUserWithIdentity(ctx, "audit-recover@test.com", true, "Recover", "", "google", "google-sub-123", "audit-recover@test.com")
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

			user, err := store.CreateUserWithIdentity(ctx, "audit-inactive-"+tt.name+"@test.com", true, "Inactive", "", "google", "google-sub-123", "audit-inactive@test.com")
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			if err := store.SetUserStatus(ctx, user.ID, tt.status); err != nil {
				t.Fatalf("set user status: %v", err)
			}

			result := svc.HandleCallback(ctx, "fake-code", "audit-inactive", "127.0.0.1", "inactive-agent")
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

	user, err := store.CreateUserWithIdentity(ctx, "audit-device-inactive@test.com", true, "Inactive Device", "", "google", "audit-device-inactive-sub", "audit-device-inactive@test.com")
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

var _ = storage.ErrNotFound
