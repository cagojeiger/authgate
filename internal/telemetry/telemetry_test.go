package telemetry

import (
	"database/sql"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestNewTelemetry_RegistersSharedCollectors(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://localhost:1/authgate")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(7)

	m := NewTelemetry(db)
	m.Security.RecordEvent("auth.inactive_user", "browser")

	assertCounterValue(t, m.Registry(), "authgate_audit_events_total", map[string]string{
		"event_type": "auth.inactive_user",
		"channel":    "browser",
	}, 1)
	assertGaugeValue(t, m.Registry(), "authgate_db_connections_max_open", nil, 7)
}
