package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
)

// captureSlog swaps the slog default with a JSON handler writing into buf for
// the duration of the test, then restores the previous default.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func newClosedAuditStorage(t *testing.T) *Storage {
	t.Helper()
	db, err := sql.Open("pgx", "postgres://localhost:1/authgate_audit_test")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
	clk := &clock.FixedClock{T: time.Date(2026, 4, 29, 0, 0, 0, 0, time.UTC)}
	return New(db, clk, idgen.CryptoGenerator{}, func(*User) error { return nil }, 15*time.Minute, 30*24*time.Hour)
}

// TestAuditLog_InsertFailure_DoesNotPropagateAndIsLogged asserts that when the
// underlying INSERT fails (here: closed *sql.DB), AuditLog still returns to the
// caller without panicking and emits an ERROR-level slog entry naming the
// event_type and user_id. Caller-provided metadata must NOT appear in the log.
func TestAuditLog_InsertFailure_DoesNotPropagateAndIsLogged(t *testing.T) {
	buf := captureSlog(t)
	store := newClosedAuditStorage(t)

	uid := "11111111-1111-4111-8111-111111111111"
	const familySecret = "family-secret-should-not-be-logged"

	// Should not panic; the new signature has no error return so the caller is
	// structurally protected. We additionally verify an ERROR log was emitted.
	store.AuditLog(context.Background(), &uid, "auth.login", "127.0.0.1", "test-agent", map[string]any{
		"family_id": familySecret,
		"client_id": "test-client",
	})

	logs := buf.String()
	if !strings.Contains(logs, `"msg":"audit log: insert"`) {
		t.Fatalf("expected insert-failure log message, got: %s", logs)
	}
	if !strings.Contains(logs, `"level":"ERROR"`) {
		t.Fatalf("expected ERROR level log, got: %s", logs)
	}
	if !strings.Contains(logs, `"event_type":"auth.login"`) {
		t.Fatalf("expected event_type attr, got: %s", logs)
	}
	if !strings.Contains(logs, `"user_id":"`+uid+`"`) {
		t.Fatalf("expected user_id attr, got: %s", logs)
	}
	if strings.Contains(logs, familySecret) {
		t.Fatalf("metadata leaked into failure log: %s", logs)
	}
}

// TestAuditLog_MarshalFailure_DoesNotPropagateAndIsLogged asserts that when
// json.Marshal of the metadata fails (channel type is unsupported), AuditLog
// logs an ERROR and returns without invoking the database insert.
func TestAuditLog_MarshalFailure_DoesNotPropagateAndIsLogged(t *testing.T) {
	buf := captureSlog(t)
	store := newClosedAuditStorage(t)

	uid := "22222222-2222-4222-8222-222222222222"
	store.AuditLog(context.Background(), &uid, "auth.signup", "", "", map[string]any{
		"unmarshalable": make(chan int),
	})

	logs := buf.String()
	if !strings.Contains(logs, `"msg":"audit log: marshal metadata"`) {
		t.Fatalf("expected marshal-failure log message, got: %s", logs)
	}
	if !strings.Contains(logs, `"level":"ERROR"`) {
		t.Fatalf("expected ERROR level log, got: %s", logs)
	}
	if !strings.Contains(logs, `"event_type":"auth.signup"`) {
		t.Fatalf("expected event_type attr, got: %s", logs)
	}
	if !strings.Contains(logs, `"user_id":"`+uid+`"`) {
		t.Fatalf("expected user_id attr, got: %s", logs)
	}
	// Insert path must not be reached; only the marshal log should be present.
	if strings.Contains(logs, `"msg":"audit log: insert"`) {
		t.Fatalf("insert log should not appear when marshal fails: %s", logs)
	}
	// Sanity: confirm the chan value never made it past json.Marshal.
	if _, err := json.Marshal(map[string]any{"unmarshalable": make(chan int)}); err == nil {
		t.Fatalf("test setup invalid: chan should be unmarshalable")
	}
}

// TestAuditLog_NilUserID_LogsEmpty asserts the signature change is safe when
// userID is nil — the failure log emits an empty user_id rather than panicking.
func TestAuditLog_NilUserID_LogsEmpty(t *testing.T) {
	buf := captureSlog(t)
	store := newClosedAuditStorage(t)

	store.AuditLog(context.Background(), nil, "auth.refresh_reuse_detected", "", "", nil)

	logs := buf.String()
	if !strings.Contains(logs, `"msg":"audit log: insert"`) {
		t.Fatalf("expected insert-failure log message, got: %s", logs)
	}
	if !strings.Contains(logs, `"user_id":""`) {
		t.Fatalf("expected empty user_id attr for nil pointer, got: %s", logs)
	}
}
