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

// hashedSessionID mirrors storage's at-rest session hashing (ADR-002): audit
// metadata stores the keyed hash of the session cookie value, never the raw
// bearer. Keys are mandatory, so this is the lookup/session HMAC.
func hashedSessionID(store *storage.Storage, s string) string {
	return store.Keys().SessionHash(s)
}

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
	svc, store, fakeUser := setupLoginService(t)
	ctx := context.Background()

	arID, _ := store.CreateTestAuthRequest(ctx, "audit-signup")
	result := svc.CompleteBrowserLogin(ctx, arID, fakeUser, "127.0.0.1", "test-agent")
	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want AutoApprove", result.Action)
	}

	user, err := store.GetUserByProviderIdentity(ctx, "google", "google-sub-123")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.signup")
	if event.Metadata["channel"] != "browser" {
		t.Fatalf("channel = %v, want browser", event.Metadata["channel"])
	}
	if event.Metadata["client_id"] != "test-app" {
		t.Fatalf("client_id = %v, want test-app (#204)", event.Metadata["client_id"])
	}
	if event.Metadata["client_name"] != "Test App" {
		t.Fatalf("client_name = %v, want Test App (#204)", event.Metadata["client_name"])
	}
}

func TestAudit002_LoginChannels(t *testing.T) {
	t.Run("browser", func(t *testing.T) {
		svc, store, fakeUser := setupBrowserExtTest(t)
		ctx := context.Background()

		user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-browser@test.com", EmailVerified: true, Name: "Browser", Provider: "google", ProviderUserID: "browser-ext-sub"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		arID, _ := store.CreateTestAuthRequest(ctx, "audit-browser")

		result := svc.CompleteBrowserLogin(ctx, arID, fakeUser, "127.0.0.1", "browser-agent")
		if result.Action != ActionAutoApprove {
			t.Fatalf("action = %v, want AutoApprove", result.Action)
		}

		event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.login")
		if event.Metadata["channel"] != "browser" {
			t.Fatalf("channel = %v, want browser", event.Metadata["channel"])
		}
	})

	t.Run("device", func(t *testing.T) {
		svc, store, clk, fakeUser := setupDeviceExtTest(t, "audit-device-sub")
		ctx := context.Background()

		user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-device@test.com", EmailVerified: true, Name: "Device", Provider: "google", ProviderUserID: "audit-device-sub"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		insertDeviceCode(t, store, "AUDT-DEV", clk)

		result := svc.CompleteDeviceLogin(ctx, "AUDT-DEV", fakeUser, "127.0.0.1", "device-agent")
		if result.Action != DeviceRedirectBack {
			t.Fatalf("action = %v, want DeviceRedirectBack", result.Action)
		}

		event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.login")
		if event.Metadata["channel"] != "device" {
			t.Fatalf("channel = %v, want device", event.Metadata["channel"])
		}
	})

	t.Run("mcp", func(t *testing.T) {
		svc, store, fakeUser := setupMCPExtTest(t, "audit-mcp-sub")
		ctx := context.Background()

		user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-mcp@test.com", EmailVerified: true, Name: "MCP", Provider: "google", ProviderUserID: "audit-mcp-sub"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		arID, _ := store.CreateTestAuthRequestWithResource(ctx, "audit-mcp", "http://localhost/mcp")

		result := svc.CompleteMCPLogin(ctx, arID, fakeUser, "127.0.0.1", "mcp-agent")
		if result.Action != ActionAutoApprove {
			t.Fatalf("action = %v, want AutoApprove", result.Action)
		}

		event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.login")
		if event.Metadata["channel"] != "mcp" {
			t.Fatalf("channel = %v, want mcp", event.Metadata["channel"])
		}
	})
}

// Issue #131: auth.login was missing when login reused an existing session and
// skipped the upstream IdP round-trip. The audit row must be written in the
// skip-IdP path with reused_session=true to keep audit history symmetric with
// the auth.token_revoked rows that follow.
func TestAudit_ReusedSession_AuthLoginRecorded(t *testing.T) {
	svc, store, _ := setupBrowserExtTest(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-reuse@test.com", EmailVerified: true, Name: "Reuse", Provider: "google", ProviderUserID: "browser-ext-sub"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, err := store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	arID, err := store.CreateTestAuthRequest(ctx, "audit-reuse")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.HandleLogin(ctx, arID, sessionID, "127.0.0.1", "reuse-agent")
	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want AutoApprove", result.Action)
	}

	event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.login")
	if event.Metadata["channel"] != "browser" {
		t.Fatalf("channel = %v, want browser", event.Metadata["channel"])
	}
	if event.Metadata["reused_session"] != true {
		t.Fatalf("reused_session = %v, want true", event.Metadata["reused_session"])
	}
	if event.Metadata["session_id"] != hashedSessionID(store, sessionID) {
		t.Fatalf("session_id = %v, want hashed %s", event.Metadata["session_id"], sessionID)
	}
}

// Issue #206: MCP reused-session auto-approve was missing auth.login.
// Mirrors TestAudit_ReusedSession_AuthLoginRecorded (browser, #131) — the MCP
// flow must also emit auth.login with reused_session=true so audit history is
// symmetric across channels.
func TestAudit_ReusedSession_MCP_AuthLoginRecorded(t *testing.T) {
	svc, store, _ := setupMCPExtTest(t, "audit-mcp-reuse-sub")
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-mcp-reuse@test.com", EmailVerified: true, Name: "MCP Reuse", Provider: "google", ProviderUserID: "audit-mcp-reuse-sub"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, err := store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	arID, err := store.CreateTestAuthRequestWithResource(ctx, "audit-mcp-reuse", "http://localhost/mcp")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.HandleLogin(ctx, arID, sessionID, "127.0.0.1", "mcp-reuse-agent")
	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want AutoApprove", result.Action)
	}

	event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.login")
	if event.Metadata["channel"] != "mcp" {
		t.Fatalf("channel = %v, want mcp", event.Metadata["channel"])
	}
	if event.Metadata["reused_session"] != true {
		t.Fatalf("reused_session = %v, want true", event.Metadata["reused_session"])
	}
	if event.Metadata["session_id"] != hashedSessionID(store, sessionID) {
		t.Fatalf("session_id = %v, want hashed %s", event.Metadata["session_id"], sessionID)
	}
	if event.Metadata["client_id"] != "test-mcp-app" {
		t.Fatalf("client_id = %v, want test-mcp-app", event.Metadata["client_id"])
	}
	if _, ok := event.Metadata["client_name"]; !ok {
		t.Fatalf("client_name key missing in metadata: %v", event.Metadata)
	}
}

func TestAudit004_DeviceApproved(t *testing.T) {
	svc, store, clk, _ := setupDeviceService(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-approve@test.com", EmailVerified: true, Name: "Approve", Provider: "google", ProviderUserID: "device-sub-123"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	insertDeviceCode(t, store, "AUDT-APRV", clk)

	result := svc.HandleDeviceApprove(ctx, "AUDT-APRV", "approve", sessionID, "127.0.0.1", "approve-agent")
	if !result.Success {
		t.Fatalf("approve failed: %s", result.Message)
	}

	event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.device_approved")
	if event.Metadata["client_id"] != "test-client" {
		t.Fatalf("client_id = %v, want test-client (#205)", event.Metadata["client_id"])
	}
	if event.Metadata["client_name"] != "Test Device Client" {
		t.Fatalf("client_name = %v, want Test Device Client (#205)", event.Metadata["client_name"])
	}
}

func TestAudit005_DeviceDenied(t *testing.T) {
	svc, store, clk, _ := setupDeviceService(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-deny@test.com", EmailVerified: true, Name: "Deny", Provider: "google", ProviderUserID: "device-sub-123"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	insertDeviceCode(t, store, "AUDT-DENY", clk)

	result := svc.HandleDeviceApprove(ctx, "AUDT-DENY", "deny", sessionID, "127.0.0.1", "deny-agent")
	if result.Success {
		t.Fatalf("deny should fail")
	}

	event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.device_denied")
	if event.Metadata["client_id"] != "test-client" {
		t.Fatalf("client_id = %v, want test-client (#205)", event.Metadata["client_id"])
	}
	if event.Metadata["client_name"] != "Test Device Client" {
		t.Fatalf("client_name = %v, want Test Device Client (#205)", event.Metadata["client_name"])
	}
}

func TestAudit006_DeletionRequested(t *testing.T) {
	loginSvc, store, fakeUser := setupLoginService(t)
	svc := NewAccountService(store)
	ctx := context.Background()

	arID, err := store.CreateTestAuthRequest(ctx, "audit-delete")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}
	loginResult := loginSvc.CompleteBrowserLogin(ctx, arID, fakeUser, "127.0.0.1", "login-agent")
	if loginResult.Action != ActionAutoApprove {
		t.Fatalf("login action = %v, want AutoApprove", loginResult.Action)
	}

	user, err := store.GetUserByProviderIdentity(ctx, "google", "google-sub-123")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	result := svc.RequestDeletion(ctx, loginResult.SessionID, "127.0.0.1", "delete-agent")
	if !result.Success {
		t.Fatalf("request deletion failed: %s", result.Message)
	}

	event := requireSingleAuditEvent(t, store.DB(), user.ID, storage.EventAuthDeletionRequested)
	if event.Metadata["channel"] != "browser" {
		t.Fatalf("channel = %v, want browser", event.Metadata["channel"])
	}
	if event.Metadata["session_id"] != hashedSessionID(store, loginResult.SessionID) {
		t.Fatalf("session_id = %v, want hashed %s", event.Metadata["session_id"], loginResult.SessionID)
	}
	if event.Metadata["client_id"] != "test-app" {
		t.Fatalf("client_id = %v, want test-app", event.Metadata["client_id"])
	}
	if event.Metadata["client_name"] != "Test App" {
		t.Fatalf("client_name = %v, want Test App", event.Metadata["client_name"])
	}
}

func TestAudit007_DeletionCancelled(t *testing.T) {
	svc, store, fakeUser := setupLoginService(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-recover@test.com", EmailVerified: true, Name: "Recover", Provider: "google", ProviderUserID: "google-sub-123"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := store.SetUserStatus(ctx, user.ID, "pending_deletion"); err != nil {
		t.Fatalf("set pending deletion: %v", err)
	}
	arID, _ := store.CreateTestAuthRequest(ctx, "audit-recover")

	result := svc.CompleteBrowserLogin(ctx, arID, fakeUser, "127.0.0.1", "recover-agent")
	if result.Action != ActionAutoApprove {
		t.Fatalf("action = %v, want AutoApprove", result.Action)
	}

	event := requireSingleAuditEvent(t, store.DB(), user.ID, storage.EventAuthDeletionCancelled)
	if event.Metadata["channel"] != "browser" {
		t.Fatalf("channel = %v, want browser", event.Metadata["channel"])
	}
	if event.Metadata["session_id"] != hashedSessionID(store, result.SessionID) {
		t.Fatalf("session_id = %v, want hashed %s", event.Metadata["session_id"], result.SessionID)
	}
	if event.Metadata["client_id"] != "test-app" {
		t.Fatalf("client_id = %v, want test-app", event.Metadata["client_id"])
	}
	if event.Metadata["client_name"] != "Test App" {
		t.Fatalf("client_name = %v, want Test App", event.Metadata["client_name"])
	}
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
			svc, store, fakeUser := setupLoginService(t)
			ctx := context.Background()

			user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-inactive-" + tt.name + "@test.com", EmailVerified: true, Name: "Inactive", Provider: "google", ProviderUserID: "google-sub-123"})
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

			result := svc.CompleteBrowserLogin(ctx, arID, fakeUser, "127.0.0.1", "inactive-agent")
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
	svc, store, clk, fakeUser := setupDeviceExtTest(t, "audit-device-inactive-sub")
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-device-inactive@test.com", EmailVerified: true, Name: "Inactive Device", Provider: "google", ProviderUserID: "audit-device-inactive-sub"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := store.SetUserStatus(ctx, user.ID, "disabled"); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	insertDeviceCode(t, store, "AUDT-INAC", clk)

	result := svc.CompleteDeviceLogin(ctx, "AUDT-INAC", fakeUser, "127.0.0.1", "device-inactive-agent")
	if result.Action != DeviceError {
		t.Fatalf("action = %v, want DeviceError", result.Action)
	}

	event := requireSingleAuditEvent(t, store.DB(), user.ID, "auth.inactive_user")
	if event.Metadata["status"] != "disabled" {
		t.Fatalf("status = %v, want disabled", event.Metadata["status"])
	}
}

func TestAuditSecurity_DevicePendingDeletionInactiveUser(t *testing.T) {
	svc, store, clk, fakeUser := setupDeviceExtTest(t, "audit-device-pending-sub")
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-device-pending@test.com", EmailVerified: true, Name: "Pending Device", Provider: "google", ProviderUserID: "audit-device-pending-sub"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := store.SetUserStatus(ctx, user.ID, "pending_deletion"); err != nil {
		t.Fatalf("set pending_deletion: %v", err)
	}
	insertDeviceCode(t, store, "AUDT-PEND", clk)

	result := svc.CompleteDeviceLogin(ctx, "AUDT-PEND", fakeUser, "127.0.0.1", "device-pending-agent")
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
			svc, store, fakeUser := setupMCPExtTest(t, "audit-mcp-"+tt.name+"-sub")
			ctx := context.Background()

			user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "audit-mcp-" + tt.name + "@test.com", EmailVerified: true, Name: "MCP Inactive", Provider: "google", ProviderUserID: "audit-mcp-" + tt.name + "-sub"})
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			if err := store.SetUserStatus(ctx, user.ID, tt.status); err != nil {
				t.Fatalf("set status %s: %v", tt.status, err)
			}
			arID, _ := store.CreateTestAuthRequestWithResource(ctx, "audit-mcp-"+tt.name, "http://localhost/mcp")

			result := svc.CompleteMCPLogin(ctx, arID, fakeUser, "127.0.0.1", "mcp-agent")
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
